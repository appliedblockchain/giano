<<<<<<< HEAD
# §6.3 — one wildcard certificate for the apex, DNS-validated through DNSimple so apply
# completes with no human intervention. Every tenant WALLET host that is either two labels
# deep or in a foreign zone needs its OWN certificate, SNI-attached to the same listener — a
# CNAME carries no certificate, and the ALB must present one valid for the hostname the
# browser actually asked for.

resource "aws_acm_certificate" "main" {
  domain_name               = local.dns_apex # dev.giano.appliedblockchain.dev
=======
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
>>>>>>> main
  subject_alternative_names = ["*.${local.dns_apex}"]
  validation_method         = "DNS"

  lifecycle { create_before_destroy = true }
<<<<<<< HEAD
  tags = { Name = "${local.name_prefix}-cert" }
}

locals {
  # Keyed by domain_name, aws_acm_certificate.main.domain_validation_options has TWO entries —
  # one for local.dns_apex, one for its "*." SAN — but ACM issues the SAME validation CNAME
  # for a domain and its own wildcard, so both entries carry an identical
  # resource_record_name/type/value. Grouping by record name (with `...` so a genuine
  # collision doesn't error) and keeping one representative per group collapses that back down
  # to the single DNS record ACM actually expects to see created.
  acm_validation_grouped = {
    for dvo in aws_acm_certificate.main.domain_validation_options :
    dvo.resource_record_name => dvo...
  }
  acm_validation_records = { for k, v in local.acm_validation_grouped : k => v[0] }
}

resource "dnsimple_zone_record" "acm_validation" {
  for_each = local.acm_validation_records

  zone_name = data.dnsimple_zone.main.name
  # DNSimple names are relative to the zone; ACM emits them fully qualified.
  name  = trimsuffix(trimsuffix(each.value.resource_record_name, "."), ".${data.dnsimple_zone.main.name}")
  type  = each.value.resource_record_type
  value = trimsuffix(each.value.resource_record_value, ".")
  ttl   = 60
=======

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
>>>>>>> main
}

resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for r in dnsimple_zone_record.acm_validation : r.qualified_name]
}

<<<<<<< HEAD
# ── Tenant wallet-host certificates — two labels deep, so the wildcard does not cover them ──
# Both dev tenants sit here on purpose (§6.3): wallet.example.* and wallet.byoui.* each get a
# certificate of their own, attached by SNI, exactly as a real client's would be. A foreign
# tenant's own wallet host (e.g. wallet.acme.com) is out of scope here — Acme's own DNS adds
# its validation record (R10) and Acme's Terraform, not this one, would own that certificate.
locals {
  extra_wallet_hosts = toset(concat(
    var.tenant_wallet_hosts[terraform.workspace],
    [local.tenant_hosts.byoui.wallet],
  ))
}

resource "aws_acm_certificate" "tenant_wallet" {
  for_each = local.extra_wallet_hosts

  domain_name       = each.value
  validation_method = "DNS"

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.name_prefix}-cert-${each.value}" }
}

resource "dnsimple_zone_record" "tenant_wallet_validation" {
  for_each = {
    # domain_validation_options is a SET of object — sets have no index, only `one()` (safe
    # here: each tenant cert carries exactly one domain, no SANs, so exactly one element).
    for host, cert in aws_acm_certificate.tenant_wallet :
    host => one(cert.domain_validation_options)
  }

  zone_name = data.dnsimple_zone.main.name
  name      = trimsuffix(trimsuffix(each.value.resource_record_name, "."), ".${data.dnsimple_zone.main.name}")
  type      = each.value.resource_record_type
  value     = trimsuffix(each.value.resource_record_value, ".")
  ttl       = 60
}

resource "aws_acm_certificate_validation" "tenant_wallet" {
  for_each = aws_acm_certificate.tenant_wallet

  certificate_arn         = each.value.arn
  validation_record_fqdns = [dnsimple_zone_record.tenant_wallet_validation[each.key].qualified_name]
}

# additional SNI certificates on the :443 listener — the wildcard remains the default.
resource "aws_lb_listener_certificate" "tenant_wallet" {
  for_each = aws_acm_certificate_validation.tenant_wallet

  listener_arn    = aws_lb_listener.https.arn
  certificate_arn = each.value.certificate_arn
}
=======
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
>>>>>>> main
