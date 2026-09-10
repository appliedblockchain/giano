# §5.7

variable "enable_deletion_protection" {
  description = "ALB deletion protection — false in dev, true in prd"
  type        = map(bool)
  default = {
    dev = false
    stg = false
    prd = true
  }
}
