variable "name_prefix" {
  type        = string
  description = "Repository namespace, e.g. giano-dev. Repositories become giano-dev/<name>."
}

variable "repository_names" {
  type        = list(string)
  description = "Image names, without the namespace, e.g. [\"wallet-api\", \"wallet-web\"]."
}

variable "keep_last_images" {
  type        = number
  description = "Lifecycle policy: images retained per repository."
  default     = 10
}

variable "force_delete" {
  type        = bool
  description = "Allow `terraform destroy` to remove non-empty repositories. Dev only."
  default     = true
}
