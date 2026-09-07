# One repository per deployed image. §11

resource "aws_ecr_repository" "repo" {
  name                 = var.repo_name
  image_tag_mutability = var.image_tag_mutability

  image_scanning_configuration {
    scan_on_push = var.scan_on_push
  }

  encryption_configuration {
    encryption_type = var.kms_key_arn == null ? "AES256" : "KMS"
    kms_key         = var.kms_key_arn
  }

  tags = merge(local.tags, { Name = var.repo_name })
}

# jsonencode(), not a .json.tpl — a template is unvalidated string
# interpolation, and a missing comma is a runtime failure with no plan-time
# signal. D19
resource "aws_ecr_lifecycle_policy" "repo" {
  repository = aws_ecr_repository.repo.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "keep the last ${var.lifecycle_image_count} images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = var.lifecycle_image_count
      }
      action = { type = "expire" }
    }]
  })
}
