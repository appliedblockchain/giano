<<<<<<< HEAD
# §9.1 — one cluster per environment. FARGATE only, no FARGATE_SPOT (D9).
=======
# One cluster per environment, plus the private DNS namespace the services
# resolve each other through. §9.1, §9.4
>>>>>>> main

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
<<<<<<< HEAD
  capacity_providers = ["FARGATE"]
=======
  capacity_providers = ["FARGATE"] # no FARGATE_SPOT — D9
>>>>>>> main

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

<<<<<<< HEAD
# ── Service discovery — §9.4 ────────────────────────────────────────────────────────────────
# so wallet-api reaches the bundler at http://bundler.giano-dev.local:4337, and wallet-web's
# nginx reaches the API at http://wallet-api.giano-dev.local:8080. Namespace names are per
# environment, so giano-stg.local never resolves in dev.
resource "aws_service_discovery_private_dns_namespace" "ns" {
  name = "${local.name_prefix}.local"
  vpc  = aws_vpc.vpc.id
=======
resource "aws_service_discovery_private_dns_namespace" "ns" {
  name        = local.service_discovery_namespace
  description = "${local.name_prefix} service discovery"
  vpc         = aws_vpc.vpc.id
>>>>>>> main

  tags = { Name = "${local.name_prefix}-cloudmap" }
}
