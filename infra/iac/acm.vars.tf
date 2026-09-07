<<<<<<< HEAD
# No environment-varying values today — which hostnames need their own certificate follows
# from var.tenant_wallet_hosts (dns.vars.tf) and local.tenant_hosts (_locals.tf), both already
# keyed by workspace. §6.3
=======
variable "acm_validation_record_ttl" {
  description = "[REQUIRED] TTL on the DNS validation records — short, they are written and read once"
  type        = number
  default     = 60
}
>>>>>>> main
