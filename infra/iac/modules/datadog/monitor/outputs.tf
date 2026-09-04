output "id" {
  description = "id of the monitor"
  value       = datadog_monitor.monitor.id
}

output "name" {
  description = "name of the monitor"
  value       = datadog_monitor.monitor.name
}
