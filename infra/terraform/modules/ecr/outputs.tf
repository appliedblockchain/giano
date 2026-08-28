output "repository_urls" {
  value       = { for k, r in aws_ecr_repository.this : k => r.repository_url }
  description = "Keyed by the short image name, e.g. wallet-api => <acct>.dkr.ecr.<region>.amazonaws.com/giano-dev/wallet-api."
}

output "repository_arns" {
  value = { for k, r in aws_ecr_repository.this : k => r.arn }
}
