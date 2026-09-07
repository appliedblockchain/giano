# §6.3 — one wildcard certificate for the apex, DNS-validated through DNSimple so apply
# completes with no human intervention. Every tenant WALLET host that is either two labels
# deep or in a foreign zone needs its OWN certificate, SNI-attached to the same listener — a
# CNAME carries no certificate, and the ALB must present one valid for the hostname the
# browser actually asked for.

resource "aws_acm_certificate" "main" {
  domain_name               = local.dns_apex # dev.giano.appliedblockchain.dev
  subject_alternative_names = ["*.${local.dns_apex}"]
  validation_method         = "DNS"

  lifecycle { create_before_destroy = true }
  tags = { Name = "${local.name_prefix}-cert" }
}

resource "dnsimple_zone_record" "acm_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options :
    dvo.domain_name => dvo
  }

  zone_name = data.dnsimple_zone.main.name
  # DNSimple names are relative to the zone; ACM emits them fully qualified.
  name  = trimsuffix(trimsuffix(each.value.resource_record_name, "."), ".${data.dnsimple_zone.main.name}")
  type  = each.value.resource_record_type
  value = trimsuffix(each.value.resource_record_value, ".")
  ttl   = 60
}

resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for r in dnsimple_zone_record.acm_validation : r.qualified_name]
}

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
    for host, cert in aws_acm_certificate.tenant_wallet :
    host => cert.domain_validation_options[0]
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
