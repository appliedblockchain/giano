variable "nat_gateway_connectivity_type" {
  description = "[REQUIRED] NAT gateway connectivity — `public` is the only value that provides egress to the internet"
  type        = string
  default     = "public"

  validation {
    condition     = contains(["public", "private"], var.nat_gateway_connectivity_type)
    error_message = "connectivity_type must be `public` or `private`."
  }
}
