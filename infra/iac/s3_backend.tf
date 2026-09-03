# Bootstrap only. §4.5, §18 step 2
#
# The one place a workspace is compared by name rather than gated on a boolean
# map (§4.1), because this resource is not per-environment at all: there is one
# state bucket for the whole project, and it is created in the `default`
# workspace before any environment exists.
#
#   terraform init -backend=false
#   terraform apply -target=module.s3-backend -auto-approve
#   terraform init -migrate-state -force-copy
#
# After that, `terraform init` alone is enough — the backend block is fully
# specified.

module "s3-backend" {
  count  = terraform.workspace == "default" ? 1 : 0
  source = "./modules/aws/s3/backend"

  bucket_name = var.s3_tfstate_name
}
