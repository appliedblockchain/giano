variable "domain" {
  type        = string
  description = "The delegated zone, e.g. dev.giano.example.com."
}

variable "parent_domain" {
  type        = string
  description = "The zone the NS record is added to by hand, e.g. giano.example.com. Comment only."
}

variable "environment" {
  type        = string
  description = "Environment discriminator, e.g. dev."
}
