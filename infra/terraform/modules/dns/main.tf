# Route 53 child zone and the ACM certificate (spec §5.1, §5.2).
#
# Separate from the ALB module because of the ordering in the runbook: this is applied first,
# on its own, so the four name servers it outputs can be added as an NS record in the PARENT
# zone — which Terraform does not manage. ACM's DNS validation blocks until that delegation
# resolves, so an all-in-one apply would simply hang.
#
#   terraform apply -target=module.dns      # then delegate, then the full apply

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}

resource "aws_route53_zone" "this" {
  name    = var.domain
  comment = "Giano ${var.environment} — delegated from ${var.parent_domain}"
}

# Apex plus wildcard: one certificate covers wallet.*, api.*, app.* and paymaster.* and
# whatever a fifth hostname turns out to be.
resource "aws_acm_certificate" "this" {
  domain_name               = var.domain
  subject_alternative_names = ["*.${var.domain}"]
  validation_method         = "DNS"

  # ACM certificates cannot be modified in place; replace before destroying so the ALB
  # listener never references a certificate that has gone away.
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "validation" {
  for_each = {
    for dvo in aws_acm_certificate.this.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
    # The wildcard validates against the same record as the apex; a map keyed on domain_name
    # collapses the duplicate, which is what ACM expects.
  }

  zone_id         = aws_route53_zone.this.zone_id
  name            = each.value.name
  type            = each.value.type
  records         = [each.value.record]
  ttl             = 60
  allow_overwrite = true
}

resource "aws_acm_certificate_validation" "this" {
  certificate_arn         = aws_acm_certificate.this.arn
  validation_record_fqdns = [for r in aws_route53_record.validation : r.fqdn]

  timeouts {
    # If this times out, the NS delegation in the parent zone is missing or has not propagated.
    create = "15m"
  }
}
