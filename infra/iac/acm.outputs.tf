output "certificate_arns" {
  description = "the wildcard certificate and one per tenant wallet host"
  value = merge(
    { (local.dns_apex) = aws_acm_certificate.main.arn },
    { for host, cert in aws_acm_certificate.tenant_wallet : host => cert.arn },
  )
}

output "TENANT_CERT_VALIDATION" {
  description = "validation records a tenant must create in ITS OWN DNS — empty while every tenant wallet host lives in our zone (§6.6 step 2)"
  value = {
    for host in local.tenant_certs_foreign : host => [
      for dvo in aws_acm_certificate.tenant_wallet[host].domain_validation_options : {
        name  = dvo.resource_record_name
        type  = dvo.resource_record_type
        value = dvo.resource_record_value
      }
    ]
  }
}
