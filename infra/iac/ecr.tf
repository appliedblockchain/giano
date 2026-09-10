# Six repositories for seven services: custom-example and
# custom-example-byoui share `example`, differing only in environment. §11
#
# ECR is how this deployment is fed. The existing GHCR push stays untouched —
# GHCR is how Giano is distributed to client projects.

module "ecr" {
  # for_each over a toset, not count over a list: with count, removing a
  # repository from the middle of the list renames — and therefore destroys
  # and recreates — every repository after it.
  for_each = toset(var.ecr_repos)
  source   = "./modules/aws/ecr"

  # The namespace includes the environment, so dev and prd images cannot
  # collide and an accidental prd pull of a dev tag is impossible.
  repo_name             = "${local.name_prefix}/${each.key}"
  image_tag_mutability  = var.ecr_image_tag_mutability[terraform.workspace]
  scan_on_push          = true
  lifecycle_image_count = var.ecr_lifecycle_image_count[terraform.workspace]
  kms_key_arn           = null # AES256; layers are not secrets

  additional_tags = { component = each.key }
}
