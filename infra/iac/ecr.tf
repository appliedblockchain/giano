# §11 — six repositories, one per deployed image. `for_each` over a `toset`, not `count` over
# a list: with count, removing a repository from the middle of the list renames — and
# therefore destroys and recreates — every repository after it.

module "ecr" {
  for_each = toset(var.ecr_repos)
  source   = "./modules/aws/ecr"

  repo_name             = "${local.name_prefix}/${each.key}"
  image_tag_mutability  = var.ecr_image_tag_mutability[terraform.workspace]
  scan_on_push          = true
  lifecycle_image_count = var.ecr_lifecycle_image_count[terraform.workspace]
  kms_key_arn           = null # AES256; image layers are not secrets

  additional_tags = local.default_tags
}
