# §17.2

variable "enable_schedule" {
  description = "on in dev, off in stg/prd"
  type        = map(bool)
  default     = { dev = true, stg = false, prd = false }
}
