terraform {
  required_version = ">= 1.10"

  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }

  backend "s3" {
    # From `terraform output bucket` in infra/terraform/bootstrap. Replace <account-id>.
    bucket = "giano-tfstate-<account-id>"
    key    = "dev/terraform.tfstate"
    region = "eu-west-2"

    encrypt = true
    # S3 native state locking (Terraform >= 1.10). No DynamoDB table to provision, pay for or
    # forget about.
    use_lockfile = true
  }
}
