# Giano — bootstrap root module. Applied ONCE, on its own, before the main root module is ever
# initialised (specs/INFRASTRUCTURE.md §4.5, §18 step 4). Creates the S3 state bucket the main
# root module's backend "s3" block points at — nothing else.
#
# Deliberately NO backend block: this module's own state stays local. The bucket cannot live in
# the state it stores, and `-backend=false` does not solve that on a fresh clone (§4.5).

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.profile
}

module "s3-backend" {
  source = "../modules/aws/s3/backend"

  bucket_name = "giano-tfstate"

  additional_tags = {
    managed_by   = "terraform"
    project_name = "giano"
  }
}
