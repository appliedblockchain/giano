variable "bucket_name" {
  description = "[REQUIRED] name of the state bucket — must match the backend block in _init.tf"
  type        = string
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
