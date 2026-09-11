# §9.2, §9.3, §14 — seven near-identical services differing only in image, size, environment,
# secrets, and whether they get an ALB target. Target groups and listener rules live inside
# the ecs-service module (§9.3), not here.

# ── wallet-api — rule 10, api.* — §9.2, §9.3, §9.6, §14.2 ──────────────────────────────────
module "svc-wallet-api" {
  source = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = "wallet-api"
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  image              = "${module.ecr["wallet-api"].repository_url}:${local.image_tag}"
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["wallet-api"].repository_arn
  cpu                = 512  # task-level
  memory             = 2048 # app 1024 + agent 256 + router 100 + headroom
  app_memory         = 1024
  container_port     = 8080
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.tasks-sg.id]

  environment = {
    GIANO_DEPLOYMENT_CLASS = "testnet"
    # No init container: wallet-api runs its own migrations on boot, before it starts
    # listening, serialised by a Postgres advisory lock — safe under concurrent replicas the
    # same way `services/tenants.ts` seeding already is. Matches
    # deploy/docker-compose.infrastructure.yml, which never had an init container either.
    RUN_MIGRATIONS            = "true"
    SPONSORSHIP_ENABLED       = "true"
    SPONSORSHIP_SIGNER_KIND   = "local"
    PAYMASTER_WATCHER_ENABLED = "true"
    LOG_LEVEL                 = "info"
    # No CHAIN_ID / RPC_URL / BUNDLER_URL / SPONSORSHIP_PAYMASTER_ADDRESS: GIANO_CHAINS
    # carries all four per chain, and the two shapes are mutually exclusive (§14.2).
    # ENTRYPOINT_ADDRESS and FACTORY_ADDRESS deliberately unset — both chains are in the
    # contracts registry and default correctly from it.
  }
  secret_arns = {
    DATABASE_URL = aws_secretsmanager_secret.database-url.arn
    # Composed by hand in 1Password, not by Terraform: each descriptor's rpcUrl embeds a
    # QuickNode key, and an ECS secret substitutes a WHOLE variable from ONE ARN (§7.3).
    GIANO_CHAINS               = module.asm-app.secret_arns["chains"]
    SPONSORSHIP_SIGNER_KEY_REF = module.asm-app.secret_arns["sponsorship-signer-key"]
    TENANTS_SEED               = module.asm-app.secret_arns["tenants-seed"]
    METRICS_BEARER_TOKEN       = module.asm-app.secret_arns["metrics-bearer-token"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 10
  alb_host_headers  = [local.hosts.api]
  health_check_path = "/healthz"
  # Must outlast the slowest migration: migrations run in-process before wallet-api starts
  # listening, so until they complete /healthz doesn't exist to answer at all.
  health_check_grace_period_seconds = 120

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nodejs"

  additional_tags = local.default_tags
}

# ── wallet-web — rule 40, wallet.* + every stock-UI tenant host — §9.2, §14.3 ───────────────
module "svc-wallet-web" {
  source = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = "wallet-web"
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  image              = "${module.ecr["wallet-web"].repository_url}:${local.image_tag}"
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["wallet-web"].repository_arn
  cpu                = 256
  memory             = 1024
  app_memory         = 512
  container_port     = 8080
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.tasks-sg.id]

  environment = {
    GIANO_WALLET_API_UPSTREAM  = "http://wallet-api.${local.name_prefix}.local:8080"
    GIANO_SPONSORSHIP_MODE     = "service"
    GIANO_ALLOWED_DAPP_ORIGINS = jsonencode(["https://${local.tenant_hosts.example.dapp}"]) # R9 — one stock-UI tenant only
    GIANO_BRAND_NAME           = var.example_brand_name
    # Both chains' RPC origins, space-separated — the browser dials each directly (§14.3).
    GIANO_CSP_CONNECT_SRC = join(" ", [var.rpc_origin, var.rpc_b_origin])
    # GIANO_RP_ID deliberately unset — load-bearing, §3.4, §14.3
  }
  secret_arns = {
    # wallet-web's own field names per chain — incompatible schema with wallet-api's
    # GIANO_CHAINS, hence a second composed secret rather than one shared blob (§7.3).
    GIANO_CHAINS = module.asm-app.secret_arns["chains-web"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled                       = true
  alb_listener_arn                  = aws_lb_listener.https.arn
  alb_rule_priority                 = 40 # placed LAST of the wallet rules — §5.7
  alb_host_headers                  = local.stock_ui_wallet_hosts
  health_check_path                 = "/"
  health_check_grace_period_seconds = 30

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nginx"

  additional_tags = local.default_tags
}

# ── custom-example — rule 20, example.* — §9.2, §14.4 ───────────────────────────────────────
module "svc-custom-example" {
  source = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = "custom-example"
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  image              = "${module.ecr["example"].repository_url}:${local.image_tag}"
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["example"].repository_arn
  cpu                = 256
  memory             = 1024
  app_memory         = 512
  container_port     = 8080
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.tasks-sg.id]

  environment = {
    GIANO_CHAIN_ID     = var.chain_id
    GIANO_CHAIN_NAME   = var.chain_name
    GIANO_CHAIN_B_ID   = var.chain_b_id
    GIANO_CHAIN_B_NAME = var.chain_b_name
    GIANO_WALLET_URL   = "https://${local.tenant_hosts.example.wallet}"
    GIANO_APP_LABEL    = var.example_brand_name
    # GIANO_TEST_ERC20 unset — the devnet default address is meaningless on a real chain
  }
  secret_arns = {
    GIANO_RPC_URL   = module.asm-app.secret_arns["rpc-url-base-sepolia"]
    GIANO_RPC_B_URL = module.asm-app.secret_arns["rpc-url-eth-sepolia"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 20
  alb_host_headers  = [local.tenant_hosts.example.dapp]
  health_check_path = "/"

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nginx"

  additional_tags = local.default_tags
}

# ── custom-example-byoui — rule 25, byoui.* — the SAME image, two values differ — §9.2, §14.4
module "svc-custom-example-byoui" {
  count  = var.byo_wallet_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = "custom-example-byoui"
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  image              = "${module.ecr["example"].repository_url}:${local.image_tag}" # same image as custom-example
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["example"].repository_arn
  cpu                = 256
  memory             = 1024
  app_memory         = 512
  container_port     = 8080
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.tasks-sg.id]

  environment = {
    GIANO_CHAIN_ID     = var.chain_id
    GIANO_CHAIN_NAME   = var.chain_name
    GIANO_CHAIN_B_ID   = var.chain_b_id
    GIANO_CHAIN_B_NAME = var.chain_b_name
    GIANO_WALLET_URL   = "https://${local.tenant_hosts.byoui.wallet}" # the whole difference from custom-example
    GIANO_APP_LABEL    = var.byoui_brand_name
  }
  secret_arns = {
    GIANO_RPC_URL   = module.asm-app.secret_arns["rpc-url-base-sepolia"]
    GIANO_RPC_B_URL = module.asm-app.secret_arns["rpc-url-eth-sepolia"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 25
  alb_host_headers  = [local.tenant_hosts.byoui.dapp]
  health_check_path = "/"

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nginx"

  additional_tags = local.default_tags
}

# ── wallet-byo — rule 35, wallet.byoui.* — tenant byoui's OWN SPA — §9.2, §14.5 ─────────────
# Deliberately NOT on the bundler security group — R11: no route to a bundler at all, which
# is what makes the open-relay vector unreachable here regardless of BYO_BUNDLER_PROXY_ENABLED.
module "svc-wallet-byo" {
  count  = var.byo_wallet_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = "wallet-byo"
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  image              = "${module.ecr["wallet-byo"].repository_url}:${local.image_tag}"
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["wallet-byo"].repository_arn
  cpu                = 256
  memory             = 1024
  app_memory         = 512
  container_port     = 8080
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.tasks-sg.id] # NOT bundler-sg — R11

  environment = {
    BYO_WALLET_PORT     = "8080"
    WALLET_API_UPSTREAM = "http://wallet-api.${local.name_prefix}.local:8080"
    CHAIN_ID            = var.chain_id
    CHAIN_B_ID          = var.chain_b_id # the fixture emits two chains only when this is set — §16.5
    SPONSORSHIP_MODE    = "service"
    # R11 — BOTH /bundler and /bundler-b must stay shut; service mode never needs either.
    BYO_BUNDLER_PROXY_ENABLED = "false"
    BYO_ALLOWED_DAPP_ORIGINS  = jsonencode(["https://${local.tenant_hosts.byoui.dapp}"])
    FACTORY_ADDRESS           = var.factory_address # required here, unlike everywhere else — §14.5
    # PAYMASTER_ADDRESS unset — service mode does not use the permissive fixture
  }
  secret_arns = {
    # Proxied same-origin, so both API keys stay server-side — §14.5
    RPC_UPSTREAM   = module.asm-app.secret_arns["rpc-url-base-sepolia"]
    RPC_B_UPSTREAM = module.asm-app.secret_arns["rpc-url-eth-sepolia"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 35 # ABOVE rule 40 — a defensive ordering, §5.7
  alb_host_headers  = [local.tenant_hosts.byoui.wallet]
  health_check_path = "/"

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nodejs"

  additional_tags = local.default_tags
}

# ── paymaster-admin — rule 30, paymaster.* — §9.2, §14.6 ────────────────────────────────────
module "svc-paymaster-admin" {
  source = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = "paymaster-admin"
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  image              = "${module.ecr["paymaster-admin"].repository_url}:${local.image_tag}"
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["paymaster-admin"].repository_arn
  cpu                = 256
  memory             = 1024
  app_memory         = 512
  container_port     = 8080
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.tasks-sg.id]

  environment = {
    GIANO_CHAIN_ID          = var.chain_id
    GIANO_PAYMASTER_ADDRESS = var.paymaster_address # the registry has no entry — must be set
    GIANO_ENVIRONMENT_LABEL = "dev (Base Sepolia)"
    GIANO_REFRESH_SECONDS   = "15"
  }
  secret_arns = {
    # Single-chain deliberately — the console has no chain switcher (§14.6).
    GIANO_RPC_URL = module.asm-app.secret_arns["rpc-url-base-sepolia"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 30
  alb_host_headers  = [local.hosts.paymaster]
  health_check_path = "/"

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nginx"

  additional_tags = local.default_tags
}

# ── bundler-base-sepolia / bundler-eth-sepolia — no ALB target — §9.2, §14.7 ────────────────
#
# Two services, one image. Alto does not multiplex chains inside one process (D3): a bundler's
# executor and submission endpoint are chain-specific, so one chain means one bundler. They
# share an executor and a utility key — one EOA funded on both chains (§13.2) — and differ in
# ALTO_RPC_URL alone.
locals {
  bundlers = {
    "bundler-base-sepolia" = module.asm-app.secret_arns["rpc-url-base-sepolia"]
    "bundler-eth-sepolia"  = module.asm-app.secret_arns["rpc-url-eth-sepolia"]
  }
}

module "svc-bundler" {
  for_each = local.bundlers
  source   = "./modules/aws/ecs-service"

  name_prefix  = local.name_prefix
  service      = each.key
  project_name = var.project_name

  cluster_arn  = aws_ecs_cluster.ecs.arn
  cluster_name = aws_ecs_cluster.ecs.name
  aws_region   = var.aws_region[terraform.workspace]
  account_id   = data.aws_caller_identity.current.account_id

  # One repository for both — same image, different ALTO_RPC_URL (§11).
  image              = "${module.ecr["bundler"].repository_url}:${local.image_tag}"
  image_tag          = local.image_tag
  ecr_repository_arn = module.ecr["bundler"].repository_arn
  cpu                = 512
  memory             = 2048
  app_memory         = 1024
  container_port     = 4337
  desired_count      = var.ecs_desired_count[terraform.workspace]

  subnet_ids         = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  security_group_ids = [aws_security_group.bundler-sg.id] # reachable only from the tasks SG

  environment = {
    ALTO_ENTRYPOINTS = var.entrypoint_address
    ALTO_SAFE_MODE   = "true" # a real chain — safe mode needs a trace-capable RPC on BOTH chains
    # GIANO_DEV_MODE deliberately unset — keeps the Anvil-key guard armed
  }
  secret_arns = {
    ALTO_RPC_URL               = each.value
    ALTO_EXECUTOR_PRIVATE_KEYS = module.asm-app.secret_arns["alto-executor-key"]
    ALTO_UTILITY_PRIVATE_KEY   = module.asm-app.secret_arns["alto-utility-key"]
  }
  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled = false # no target group, no listener rule, no hostname

  vpc_id                 = aws_vpc.vpc.id
  service_discovery_id   = aws_service_discovery_private_dns_namespace.ns.id
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]
  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = "nodejs"

  additional_tags = local.default_tags
}
