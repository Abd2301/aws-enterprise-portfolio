# ============================================================
# CI/CD Production values - no AWS profile (uses OIDC role)
# ============================================================

aws_region     = "us-east-1"
aws_account_id = "159326043807"

vpc_id = "vpc-0a8603b7252882ecf"

private_subnet_ids = [
  "subnet-047dc11d271284e5f",
  "subnet-0d57dd68ac65b218f",
  "subnet-09bb57307a83747e6"
]