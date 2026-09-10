# One cluster per environment, plus the private DNS namespace the services
# resolve each other through. §9.1, §9.4

resource "aws_ecs_cluster" "ecs" {
  name = "${local.name_prefix}-ecs"

  setting {
    name  = "containerInsights"
    value = var.ecs_container_insights[terraform.workspace]
  }

  tags = { Name = "${local.name_prefix}-ecs" }
}

resource "aws_ecs_cluster_capacity_providers" "ecs" {
  cluster_name       = aws_ecs_cluster.ecs.name
  capacity_providers = ["FARGATE"] # no FARGATE_SPOT — D9

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_service_discovery_private_dns_namespace" "ns" {
  name        = local.service_discovery_namespace
  description = "${local.name_prefix} service discovery"
  vpc         = aws_vpc.vpc.id

  tags = { Name = "${local.name_prefix}-cloudmap" }
}
