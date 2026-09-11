output "dns_zone_name" {
  value = data.dnsimple_zone.main.name
}

output "dns_apex" {
  value = local.dns_apex
}
