# DNS is DNSimple. There is no Route 53 hosted zone, no NS delegation and no
# manual handover step. §6
#
# Terraform does NOT create the zone: it creates records in a zone that must
# already exist in the DNSimple account. Asserting that with a data source
# means a typo or a missing domain fails at plan time with a clear message
# instead of on the first record write. §18 step 1 checks it too.

data "dnsimple_zone" "main" {
  name = local.dns_zone
}

locals {
  # Six CNAMEs to the ALB, plus one from the stock-UI tenant's wallet host to
  # Giano's. The apex is left unset — nothing is served there. §6.4
  #
  # The example tenant's record is deliberately not shortcut to a direct ALB
  # CNAME even though Terraform owns both names and it would resolve
  # identically: the point is that it is the SAME record a tenant creates in
  # their own DNS. Shortcut it and the CNAME path — the one thing this
  # environment exists to rehearse — is never exercised.
  dns_records = merge(
    {
      (local.hosts.wallet)              = { type = "CNAME", value = aws_lb.alb.dns_name }
      (local.hosts.api)                 = { type = "CNAME", value = aws_lb.alb.dns_name }
      (local.hosts.paymaster)           = { type = "CNAME", value = aws_lb.alb.dns_name }
      (local.tenant_hosts.example.dapp) = { type = "CNAME", value = aws_lb.alb.dns_name }
    },
    # The stock-UI tenant's wallet host is created only where it is actually a
    # stock-UI tenant of this environment — the same list rule 40 and the SNI
    # certificates are built from. That keeps DNS, the certificate and the
    # listener in agreement by construction: a hostname that resolves here but
    # carries no certificate of its own would be served the wildcard, which
    # does not cover two labels.
    contains(local.tenant_wallet_hosts, local.tenant_hosts.example.wallet) ? {
      (local.tenant_hosts.example.wallet) = { type = "CNAME", value = local.hosts.wallet }
    } : {},
    # A BYO tenant has nothing of Giano's to point at: its wallet origin is
    # its own deployment, which here happens to sit behind the same ALB.
    var.byo_wallet_enabled[terraform.workspace] ? {
      (local.tenant_hosts.byoui.dapp)   = { type = "CNAME", value = aws_lb.alb.dns_name }
      (local.tenant_hosts.byoui.wallet) = { type = "CNAME", value = aws_lb.alb.dns_name }
    } : {},
  )
}

# A single for_each over a local map reads better than an indirection through
# modules/dnsimple/record-set, which is why that module does not exist yet.
# §6.5
resource "dnsimple_zone_record" "record" {
  for_each = local.dns_records

  zone_name = data.dnsimple_zone.main.name

  # DNSimple record names are relative to the registrable zone.
  name  = trimsuffix(each.key, ".${local.dns_zone}")
  type  = each.value.type
  value = each.value.value
  ttl   = var.dns_record_ttl
}
