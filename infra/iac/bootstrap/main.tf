# The state bucket, and nothing else. §4.5, §18 step 4
#
# A SEPARATE root module, applied once, with LOCAL state — and deliberately no
# `backend` block, which is the whole point of the directory.
#
# `-backend=false` in the main root module does not solve the chicken-and-egg:
# it means "reuse whatever backend is already initialised", which on a fresh
# clone is nothing, so the declared backend "s3" stays uninitialised and the
# very next command fails with "Backend initialization required". There is no
# ordering of flags around it, because that configuration declares a backend
# pointing at a bucket that does not exist yet. A root module with no backend
# block has no such problem.
#
# Keeping it separate also keeps it small: this needs only the AWS provider.
# Creating the bucket from the main root module — even with -target — drags in
# the 1Password, DNSimple and Datadog providers and the secret-inventory data
# source, none of which have anything to do with an S3 bucket.
#
# This module's own state stays local. It describes one bucket and holds
# nothing sensitive, so losing it costs a `terraform import` and nothing else.
# DO NOT migrate it into the bucket it manages.

terraform {
  required_version = ">= 1.11"

  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.profile

  default_tags {
    tags = {
      managed_by   = "terraform"
      org_name     = var.org_name
      project_name = var.project_name

      # No `env` and no `tfstate` from §4.3: this bucket is project-wide
      # rather than per-environment, and its own state is local.
    }
  }
}

module "s3-backend" {
  source = "../modules/aws/s3/backend"

  bucket_name = var.s3_tfstate_name
}
