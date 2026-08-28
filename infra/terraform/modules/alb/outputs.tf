output "https_listener_arn" {
  value       = aws_lb_listener.https.arn
  description = "Each ecs-service attaches its own host-header rule to this listener."
}

output "dns_name" {
  value = aws_lb.this.dns_name
}

output "zone_id" {
  value       = aws_lb.this.zone_id
  description = "For Route 53 A-alias records."
}

output "arn_suffix" {
  value       = aws_lb.this.arn_suffix
  description = "For CloudWatch metric dimensions, if alarms are ever added."
}
