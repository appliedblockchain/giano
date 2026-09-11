output "acm_certificate_arn" {
  description = "the wildcard certificate, the HTTPS listener's default"
  value       = aws_acm_certificate_validation.main.certificate_arn
}

output "tenant_wallet_certificate_arns" {
  description = "{ hostname => certificate ARN } for every wallet host outside the wildcard"
  value       = { for host, v in aws_acm_certificate_validation.tenant_wallet : host => v.certificate_arn }
}
