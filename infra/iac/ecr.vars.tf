variable "ecr_repos" {
  description = "[REQUIRED] the images this deployment runs. Six repositories for seven services — custom-example and custom-example-byoui share `example`"
  type        = list(string)
  default = [
    "wallet-api",
    "wallet-web",
    "paymaster-admin",
    "example",
    "wallet-byo",
    "bundler",
  ]
}

variable "ecr_image_tag_mutability" {
  description = "[REQUIRED] tag mutability, per environment. IMMUTABLE everywhere: tags are the commit SHA, never `latest`, and the registry should enforce that rather than CI being trusted to"
  type        = map(string)
  default     = { dev = "IMMUTABLE", stg = "IMMUTABLE", prd = "IMMUTABLE" }
}

variable "ecr_lifecycle_image_count" {
  description = "[REQUIRED] how many images each repository keeps, per environment. This is a RETENTION FLOOR for var.image_tag, not just a cost setting: the lifecycle rule expires on `tagStatus: any` (modules/aws/ecr), docker.yml publishes on every push to main, and the deployed tag is pinned rather than latest — so a pinned tag more than this many main-pushes old has been deleted out from under its own service. It surfaces on the next task placement, not on the apply that pinned it, which is the worst time to find out. 30 in dev is roughly a fortnight of main at current volume"
  type        = map(number)
  default     = { dev = 30, stg = 30, prd = 30 }
}
