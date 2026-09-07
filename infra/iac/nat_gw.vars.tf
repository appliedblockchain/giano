<<<<<<< HEAD
# No environment-varying values today — NAT count (two, one per AZ) and placement are fixed
# by design and do not change between workspaces (D8, D9, §5.4). This file exists as the
# sibling §4.2 names, ready for the day that changes.
=======
variable "nat_gateway_connectivity_type" {
  description = "[REQUIRED] NAT gateway connectivity — `public` is the only value that provides egress to the internet"
  type        = string
  default     = "public"

  validation {
    condition     = contains(["public", "private"], var.nat_gateway_connectivity_type)
    error_message = "connectivity_type must be `public` or `private`."
  }
}
>>>>>>> main
