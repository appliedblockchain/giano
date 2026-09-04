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
  description = "[REQUIRED] how many images each repository keeps, per environment"
  type        = map(number)
  default     = { dev = 10, stg = 10, prd = 30 }
}
