output "alb_arn" {
  description = "the ALB's ARN"
  value       = aws_lb.alb.arn
}

output "alb_dns_name" {
  description = "the ALB's DNS name — the target of the apex/wildcard alias records (§6)"
  value       = aws_lb.alb.dns_name
}

output "alb_zone_id" {
  description = "the ALB's hosted zone id — required alongside alb_dns_name for an alias record"
  value       = aws_lb.alb.zone_id
}

output "https_listener_arn" {
  description = "the :443 listener — every per-service listener rule attaches here"
  value       = aws_lb_listener.https.arn
}
