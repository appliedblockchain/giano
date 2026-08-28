# One ECR repository per deployed image (spec §10.1).
#
# GHCR is untouched and stays the DISTRIBUTION channel for client projects; ECR is only how
# this deployment is fed. docker.yml's giano-devnet and giano-contracts-deployer are not
# deployed here and stay GHCR-only.
#
# Tags are immutable and are the commit SHA, never `latest`. A mutable tag means the deployed
# artefact cannot be identified from the console, which is the first question anyone asks of a
# misbehaving environment.

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

resource "aws_ecr_repository" "this" {
  for_each = toset(var.repository_names)

  name                 = "${var.name_prefix}/${each.value}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = var.force_delete

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  for_each   = aws_ecr_repository.this
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep the last ${var.keep_last_images} images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = var.keep_last_images
      }
      action = { type = "expire" }
    }]
  })
}
