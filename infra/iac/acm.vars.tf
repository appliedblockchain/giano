variable "acm_validation_record_ttl" {
  description = "[REQUIRED] TTL on the DNS validation records — short, they are written and read once"
  type        = number
  default     = 60
}
