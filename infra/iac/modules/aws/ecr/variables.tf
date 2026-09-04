variable "repo_name" {
  description = "[REQUIRED] repository name, including the environment namespace, e.g. giano-dev/wallet-api"
  type        = string
}

variable "image_tag_mutability" {
  description = "[REQUIRED] IMMUTABLE or MUTABLE. IMMUTABLE everywhere: a tag that can be repointed means the deployed artefact cannot be identified from the console"
  type        = string

  validation {
    condition     = contains(["IMMUTABLE", "MUTABLE"], var.image_tag_mutability)
    error_message = "image_tag_mutability must be IMMUTABLE or MUTABLE."
  }
}

variable "scan_on_push" {
  description = "[REQUIRED] basic scanning on push — free"
  type        = bool
  default     = true
}

variable "lifecycle_image_count" {
  description = "[REQUIRED] how many images to keep"
  type        = number
}

variable "kms_key_arn" {
  description = "[OPTIONAL] CMK for layer encryption. null selects AES256 — image layers are not secrets, and a CMK complicates cross-account pulls later"
  type        = string
  default     = null
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
