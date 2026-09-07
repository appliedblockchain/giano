<<<<<<< HEAD
output "monitor_id" {
  value = datadog_monitor.this.id
}

output "monitor_name" {
  value = datadog_monitor.this.name
=======
output "id" {
  description = "id of the monitor"
  value       = datadog_monitor.monitor.id
}

output "name" {
  description = "name of the monitor"
  value       = datadog_monitor.monitor.name
>>>>>>> main
}
