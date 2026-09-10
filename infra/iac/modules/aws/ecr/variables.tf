# §11

variable "repo_name" {
  description = "[REQUIRED] full repository name, e.g. giano-dev/wallet-api"
  type        = string
}

variable "image_tag_mutability" {
  description = "[REQUIRED] MUTABLE or IMMUTABLE"
  type        = string
}

variable "scan_on_push" {
  description = "[REQUIRED] whether to run basic image scanning on push"
  type        = bool
}

variable "lifecycle_image_count" {
  description = "[REQUIRED] number of images to keep; older images expire"
  type        = number
}

variable "kms_key_arn" {
  description = "[OPTIONAL] KMS key ARN to encrypt the repository with; null uses AES256"
  type        = string
  default     = null
  nullable    = true
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
