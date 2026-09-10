output "alb_dns_name" {
  description = "the ALB's DNS name — every hostname in this environment CNAMEs to it"
  value       = aws_lb.alb.dns_name
}

output "alb_arn" {
  description = "ARN of the load balancer"
  value       = aws_lb.alb.arn
}

output "alb_https_listener_arn" {
  description = "ARN of the HTTPS listener the ecs-service module attaches its rules to"
  value       = aws_lb_listener.https.arn
}

output "alb_zone_id" {
  description = "the ALB's hosted zone id — unused by DNSimple, kept for a future ALIAS record"
  value       = aws_lb.alb.zone_id
}
