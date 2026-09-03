output "dns_zone" {
  description = "the DNSimple zone records are written into"
  value       = data.dnsimple_zone.main.name
}

output "dns_apex" {
  description = "the apex every hostname in this environment hangs off"
  value       = local.dns_apex
}

output "dns_records" {
  description = "{ hostname => qualified name } for every record Terraform owns"
  value       = { for host, record in dnsimple_zone_record.record : host => record.qualified_name }
}
