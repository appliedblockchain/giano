# §6 — DNSimple, via the dnsimple/dnsimple provider. Terraform does not create the zone; it
# creates records IN a zone that must already exist (§18.1 step 1).

data "dnsimple_zone" "main" {
  name = local.dns_zone
}

locals {
  # Six CNAMEs to the ALB, plus one CNAME from wallet.example.* to Giano's own wallet host —
  # §6.4. What wallet.byoui.* and wallet.example.* point AT is the entire DNS-level
  # difference between the two tenant topologies.
  dns_records = {
    (local.hosts.wallet)                = aws_lb.alb.dns_name
    (local.hosts.api)                   = aws_lb.alb.dns_name
    (local.hosts.paymaster)             = aws_lb.alb.dns_name
    (local.tenant_hosts.example.dapp)   = aws_lb.alb.dns_name
    (local.tenant_hosts.byoui.dapp)     = aws_lb.alb.dns_name
    (local.tenant_hosts.byoui.wallet)   = aws_lb.alb.dns_name
    (local.tenant_hosts.example.wallet) = local.hosts.wallet
  }
}

resource "dnsimple_zone_record" "records" {
  for_each = local.dns_records

  zone_name = data.dnsimple_zone.main.name
  name      = trimsuffix(each.key, ".${data.dnsimple_zone.main.name}")
  type      = "CNAME"
  value     = "${each.value}."
  ttl       = 60
}
