output "zone_id" {
  value = aws_route53_zone.this.zone_id
}

output "name_servers" {
  value       = aws_route53_zone.this.name_servers
  description = "Add these as an NS record for the child zone in the parent zone. Runbook step 2."
}

output "certificate_arn" {
  # The validation resource, not the certificate: depending on this is what makes the ALB
  # listener wait until the certificate is actually issued.
  value = aws_acm_certificate_validation.this.certificate_arn
}

output "domain" {
  value = var.domain
}
