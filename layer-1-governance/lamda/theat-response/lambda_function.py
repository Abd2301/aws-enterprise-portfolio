import boto3
import json
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main handler - receives GuardDuty finding from EventBridge
    Routes to appropriate remediation based on resource type
    """
    
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Extract finding details from EventBridge event
    # EventBridge wraps the GuardDuty finding in a 'detail' key
    finding = event.get('detail', {})
    
    # Get finding severity (LOW=1-3, MEDIUM=4-6, HIGH=7-10)
    severity = finding.get('severity', 0)
    
    # Get the type of threat detected
    finding_type = finding.get('type', 'Unknown')
    
    # Get affected resource details
    resource = finding.get('resource', {})
    resource_type = resource.get('resourceType', 'Unknown')
    
    # Get account where threat was detected
    account_id = finding.get('accountId', 'Unknown')
    
    # Get finding ID for reference
    finding_id = finding.get('id', 'Unknown')
    
    logger.info(f"Processing finding: {finding_type}, Severity: {severity}, Resource: {resource_type}")
    
    # SNS topic for notifications
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    
    # Route to appropriate remediation based on resource type
    if resource_type == 'Instance':
        # EC2 instance compromise
        remediate_ec2(resource, account_id, finding_type, sns_topic_arn)
        
    elif resource_type == 'AccessKey':
        # IAM credential compromise
        remediate_iam(resource, account_id, finding_type, sns_topic_arn)
        
    else:
        # Unknown resource type - just notify
        notify_security_team(
            sns_topic_arn,
            f"GuardDuty Alert: {finding_type}",
            f"Account: {account_id}\nFinding ID: {finding_id}\nResource Type: {resource_type}\nSeverity: {severity}"
        )
    
    return {
        'statusCode': 200,
        'body': 'Remediation complete'
    }


def remediate_ec2(resource, account_id, finding_type, sns_topic_arn):
    """
    Isolates compromised EC2 instance by replacing its security group
    with a deny-all security group
    """
    
    # Extract instance details
    instance_details = resource.get('instanceDetails', {})
    instance_id = instance_details.get('instanceId', 'Unknown')
    
    if instance_id == 'Unknown':
        logger.error("No instance ID found in finding")
        return
    
    logger.info(f"Isolating EC2 instance: {instance_id}")
    
    ec2 = boto3.client('ec2')
    
    try:
        # Step 1: Get the instance's VPC ID to create isolation SG in same VPC
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        vpc_id = instance.get('VpcId', '')
        
        # Step 2: Create isolation security group with NO inbound or outbound rules
        # This effectively cuts off all network access to the instance
        isolation_sg = ec2.create_security_group(
            GroupName=f'ISOLATION-{instance_id}',
            Description=f'Isolation SG for compromised instance {instance_id}',
            VpcId=vpc_id
        )
        isolation_sg_id = isolation_sg['GroupId']
        
        # Step 3: Remove default outbound rule (allows all traffic by default)
        ec2.revoke_security_group_egress(
            GroupId=isolation_sg_id,
            IpPermissions=[{
                'IpProtocol': '-1',  # All protocols
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        
        # Step 4: Replace instance's security groups with isolation SG
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )
        
        logger.info(f"Successfully isolated instance {instance_id} with SG {isolation_sg_id}")
        
        # Step 5: Notify security team
        notify_security_team(
            sns_topic_arn,
            f"AUTOMATED ISOLATION: EC2 Instance {instance_id}",
            f"""
AUTOMATED THREAT RESPONSE EXECUTED

Finding Type: {finding_type}
Account: {account_id}
Instance ID: {instance_id}
Action Taken: Instance isolated with deny-all security group {isolation_sg_id}

The instance has been cut off from all network access.
Please investigate and take further action.
            """
        )
        
    except Exception as e:
        logger.error(f"Failed to isolate instance {instance_id}: {str(e)}")
        notify_security_team(
            sns_topic_arn,
            f"REMEDIATION FAILED: EC2 {instance_id}",
            f"Failed to isolate instance {instance_id}. Manual intervention required.\nError: {str(e)}"
        )


def remediate_iam(resource, account_id, finding_type, sns_topic_arn):
    """
    Deactivates compromised IAM access key
    """
    
    # Extract access key details
    access_key_details = resource.get('accessKeyDetails', {})
    access_key_id = access_key_details.get('accessKeyId', 'Unknown')
    username = access_key_details.get('userName', 'Unknown')
    
    if access_key_id == 'Unknown':
        logger.error("No access key ID found in finding")
        return
        
    logger.info(f"Deactivating access key: {access_key_id} for user: {username}")
    
    iam = boto3.client('iam')
    
    try:
        # Deactivate the compromised access key
        # We deactivate rather than delete to preserve forensic evidence
        iam.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'  # Deactivate, don't delete - preserves evidence
        )
        
        logger.info(f"Successfully deactivated access key {access_key_id}")
        
        # Notify security team
        notify_security_team(
            sns_topic_arn,
            f"AUTOMATED KEY REVOCATION: {username}",
            f"""
AUTOMATED THREAT RESPONSE EXECUTED

Finding Type: {finding_type}
Account: {account_id}
Username: {username}
Access Key: {access_key_id}
Action Taken: Access key deactivated

Please investigate the user account for further compromise.
Consider forcing password reset and reviewing CloudTrail for this user.
            """
        )
        
    except Exception as e:
        logger.error(f"Failed to deactivate key {access_key_id}: {str(e)}")
        notify_security_team(
            sns_topic_arn,
            f"REMEDIATION FAILED: IAM Key {access_key_id}",
            f"Failed to deactivate key {access_key_id}. Manual intervention required.\nError: {str(e)}"
        )


def notify_security_team(sns_topic_arn, subject, message):
    """
    Sends notification to security team via SNS
    """
    if not sns_topic_arn:
        logger.error("SNS_TOPIC_ARN environment variable not set")
        return
        
    sns = boto3.client('sns')
    
    try:
        sns.publish(
            TopicArn=sns_topic_arn,
            Subject=subject[:100],  # SNS subject limit is 100 chars
            Message=message
        )
        logger.info(f"Notification sent: {subject}")
        
    except Exception as e:
        logger.error(f"Failed to send SNS notification: {str(e)}")