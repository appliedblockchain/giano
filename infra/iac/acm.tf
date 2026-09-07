# ACM certificates, in-region, DNS-validated through DNSimple. §6.3
#
# WebAuthn needs a real HTTPS origin, and the ALB must present a certificate
# valid for the hostname the browser asked for. Giano's own hostnames ride one
# wildcard; every tenant WALLET host needs a certificate of its own, because a
# CNAME carries none and both dev tenants sit two labels under the apex, where
# a wildcard does not reach.

locals {
  # Two independent things put a tenant's wallet host outside the wildcard,
  # and either alone is enough: depth (both dev tenants, in our zone) or a
  # foreign zone (every real client). The only difference is who creates the
  # validation record — Terraform for a host in our zone, the tenant for one
  # in theirs (R10).
  tenant_certs_in_zone = toset([
    for host in local.tenant_cert_hosts : host if endswith(host, ".${local.dns_zone}")
  ])

  tenant_certs_foreign = toset([
    for host in local.tenant_cert_hosts : host if !endswith(host, ".${local.dns_zone}")
  ])
}

# --- Giano's own hostnames ------------------------------------------------

resource "aws_acm_certificate" "main" {
  domain_name               = local.dns_apex
  subject_alternative_names = ["*.${local.dns_apex}"]
  validation_method         = "DNS"

  lifecycle { create_before_destroy = true }

  tags = { Name = "${local.name_prefix}-cert" }
}

resource "dnsimple_zone_record" "acm_validation" {
  # The wildcard SAN validates at the same record as the apex it covers, so
  # ACM emits an identical name and value for both. DNSimple has no upsert, so
  # keep one record per distinct validation name — and key the map on
  # domain_name, which comes from configuration and is therefore known at plan
  # time. Keying on resource_record_name would not be.
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options :
    dvo.domain_name => dvo if !startswith(dvo.domain_name, "*.")
  }

  zone_name = data.dnsimple_zone.main.name

  # ACM returns `_x1.dev.giano.appliedblockchain.dev.`; DNSimple wants
  # `_x1.dev.giano`, relative to the zone. Getting this wrong produces a
  # record at `…appliedblockchain.dev.appliedblockchain.dev`, which validates
  # nothing and takes an hour to spot.
  name  = trimsuffix(trimsuffix(each.value.resource_record_name, "."), ".${local.dns_zone}")
  type  = each.value.resource_record_type
  value = trimsuffix(each.value.resource_record_value, ".")
  ttl   = var.acm_validation_record_ttl
}

resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for r in dnsimple_zone_record.acm_validation : r.qualified_name]
}

# --- Tenant wallet hosts --------------------------------------------------
#
# One certificate per tenant wallet hostname, attached to the same HTTPS
# listener as an additional SNI certificate (alb.tf). ACM picks the
# certificate per connection from SNI; the wildcard remains the default.

resource "aws_acm_certificate" "tenant_wallet" {
  for_each = local.tenant_cert_hosts

  domain_name       = each.key
  validation_method = "DNS"

  lifecycle { create_before_destroy = true }

  tags = { Name = "${local.name_prefix}-cert-${replace(each.key, ".", "-")}" }
}

# Only for hosts in our own zone. A tenant hosting its wallet origin in its
# own DNS adds the validation CNAME itself — and must LEAVE it in place, or
# ACM stops renewing about thirteen months later (R10, §6.6 step 2).
resource "dnsimple_zone_record" "tenant_wallet_validation" {
  for_each = local.tenant_certs_in_zone

  zone_name = data.dnsimple_zone.main.name

  name = trimsuffix(trimsuffix(
    one(aws_acm_certificate.tenant_wallet[each.key].domain_validation_options).resource_record_name,
  "."), ".${local.dns_zone}")

  type  = one(aws_acm_certificate.tenant_wallet[each.key].domain_validation_options).resource_record_type
  value = trimsuffix(one(aws_acm_certificate.tenant_wallet[each.key].domain_validation_options).resource_record_value, ".")
  ttl   = var.acm_validation_record_ttl
}

resource "aws_acm_certificate_validation" "tenant_wallet" {
  for_each = local.tenant_certs_in_zone

  certificate_arn         = aws_acm_certificate.tenant_wallet[each.key].arn
  validation_record_fqdns = [dnsimple_zone_record.tenant_wallet_validation[each.key].qualified_name]
}
