variable "bucket_name" {
<<<<<<< HEAD
  description = "[REQUIRED] name of the S3 bucket that holds Terraform state for the whole project"
=======
  description = "[REQUIRED] name of the state bucket — must match the backend block in _init.tf"
>>>>>>> main
  type        = string
}

variable "additional_tags" {
  description = "[OPTIONAL] additional tags to be attached to the resources"
  type        = map(any)
  default     = {}
}
