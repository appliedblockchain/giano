variable "bucket_name" {
  description = "[REQUIRED] name of the S3 bucket that holds Terraform state for the whole project"
  type        = string
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
