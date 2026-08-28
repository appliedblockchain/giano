# Giano dev environment (specs/DEV-INFRASTRUCTURE.md).
#
# ECS Fargate on Base Sepolia: four public hostnames behind one ALB, a private Alto bundler,
# RDS Postgres in private subnets, no NAT Gateway.
#
# Bring-up is NOT a single apply. See specs/DEV-INFRASTRUCTURE.md §16; the short version:
#
#   1. bootstrap/            the state bucket
#   2. apply -target=module.dns, then add the NS record in the parent zone
#   3. deploy + provision GianoPaymaster on Base Sepolia, fund the executor
#   4. aws ssm put-parameter for the four placeholder secrets
#   5. apply                 (services fail to start — ECR is empty. Expected.)
#   6. push images, run the migrate task, provision sponsorship

data "aws_caller_identity" "current" {}

locals {
  name   = "giano-${var.environment}"
  domain = "${var.subdomain}.${var.parent_domain}"

  hosts = {
    wallet    = "wallet.${var.subdomain}.${var.parent_domain}"
    api       = "api.${var.subdomain}.${var.parent_domain}"
    app       = "app.${var.subdomain}.${var.parent_domain}"
    paymaster = "paymaster.${var.subdomain}.${var.parent_domain}"
  }

  # Cloud Map names. This is what replaces compose's service names.
  internal = {
    wallet_api = "http://wallet-api.${local.name}.local:8080"
    bundler    = "http://bundler.${local.name}.local:4337"
  }

  images = ["wallet-api", "wallet-web", "custom-example", "paymaster-admin", "bundler"]

  # Every service the scheduler scales and CI deploys.
  service_names = ["wallet-api", "wallet-web", "custom-example", "paymaster-admin", "bundler"]
}

# ── foundation ─────────────────────────────────────────────────────────────────────────────

module "network" {
  source = "../../modules/network"

  name     = local.name
  region   = var.region
  vpc_cidr = var.vpc_cidr
}

# Applied on its own first: the NS delegation into the parent zone is manual, and ACM
# validation blocks until it resolves.
module "dns" {
  source = "../../modules/dns"

  domain        = local.domain
  parent_domain = var.parent_domain
  environment   = var.environment
}

module "ecr" {
  source = "../../modules/ecr"

  name_prefix      = local.name
  repository_names = local.images
}

module "alb" {
  source = "../../modules/alb"

  name              = local.name
  security_group_id = module.network.alb_security_group_id
  public_subnet_ids = module.network.public_subnet_ids
  certificate_arn   = module.dns.certificate_arn
}

module "cluster" {
  source = "../../modules/ecs-cluster"

  name                        = local.name
  vpc_id                      = module.network.vpc_id
  service_discovery_namespace = "${local.name}.local"
  ssm_path_prefix             = local.ssm_prefix
}

module "rds" {
  source = "../../modules/rds"

  name              = local.name
  subnet_ids        = module.network.private_subnet_ids
  security_group_id = module.network.rds_security_group_id
  ssm_path_prefix   = local.ssm_prefix
}

# ── DNS records ────────────────────────────────────────────────────────────────────────────

resource "aws_route53_record" "hosts" {
  for_each = local.hosts

  zone_id = module.dns.zone_id
  name    = each.value
  type    = "A"

  alias {
    name                   = module.alb.dns_name
    zone_id                = module.alb.zone_id
    evaluate_target_health = false
  }
}

# ── shared service wiring ──────────────────────────────────────────────────────────────────

locals {
  service_common = {
    cluster_id                     = module.cluster.cluster_id
    cluster_name                   = module.cluster.cluster_name
    region                         = var.region
    vpc_id                         = module.network.vpc_id
    subnet_ids                     = module.network.public_subnet_ids
    execution_role_arn             = module.cluster.execution_role_arn
    service_discovery_namespace_id = module.cluster.service_discovery_namespace_id
    listener_arn                   = module.alb.https_listener_arn
    image_tag                      = var.image_tag
  }

  rpc_url_arn = aws_ssm_parameter.placeholder["rpc-url"].arn
}

# ── wallet-api ─────────────────────────────────────────────────────────────────────────────
#
# Single-chain shorthand (CHAIN_ID/RPC_URL/BUNDLER_URL), not GIANO_CHAINS: one chain is served
# and the two shapes are mutually exclusive by design.
#
# ENTRYPOINT_ADDRESS and FACTORY_ADDRESS are deliberately unset. 84532 is in the contracts
# registry and they default correctly from it; setting them by hand is how they drift from the
# canonical freeze that the boot-time chain check enforces.

module "wallet_api" {
  source = "../../modules/ecs-service"

  service_name       = "wallet-api"
  image_url          = module.ecr.repository_urls["wallet-api"]
  cpu                = 512
  memory             = 1024
  security_group_ids = [module.network.tasks_security_group_id]

  alb_host          = local.hosts.api
  listener_priority = 10
  health_check_path = "/healthz"

  health_check_command      = ["CMD-SHELL", "curl -fsS http://127.0.0.1:8080/healthz || exit 1"]
  health_check_start_period = 60 # migrations may still be settling on a cold database

  environment = {
    # What this deployment IS. `testnet` is what makes SPONSORSHIP_SIGNER_KIND=local legal:
    # loadConfig refuses a local key under `production`, and the `hsm` path needs an adapter
    # passed to buildApp that the published image does not wire (spec §9.3).
    GIANO_DEPLOYMENT_CLASS = "testnet"

    # False on the service. A rolling deploy with two tasks racing to migrate is a bad way to
    # learn about advisory locks — the one-shot task in tasks.tf owns the schema.
    RUN_MIGRATIONS = "false"

    CHAIN_ID    = tostring(var.chain_id)
    BUNDLER_URL = local.internal.bundler

    SPONSORSHIP_ENABLED           = tostring(var.sponsorship_enabled)
    SPONSORSHIP_SIGNER_KIND       = "local"
    SPONSORSHIP_PAYMASTER_ADDRESS = var.paymaster_address
    PAYMASTER_WATCHER_ENABLED     = tostring(var.sponsorship_enabled)

    LOG_LEVEL = "info"
  }

  secrets = {
    DATABASE_URL               = module.rds.database_url_parameter_arn
    RPC_URL                    = local.rpc_url_arn
    TENANTS_SEED               = aws_ssm_parameter.tenants_seed.arn
    METRICS_BEARER_TOKEN       = aws_ssm_parameter.metrics_token.arn
    SPONSORSHIP_SIGNER_KEY_REF = aws_ssm_parameter.placeholder["sponsorship-signer-key"].arn
  }

  cluster_id                     = local.service_common.cluster_id
  cluster_name                   = local.service_common.cluster_name
  region                         = local.service_common.region
  vpc_id                         = local.service_common.vpc_id
  subnet_ids                     = local.service_common.subnet_ids
  execution_role_arn             = local.service_common.execution_role_arn
  service_discovery_namespace_id = local.service_common.service_discovery_namespace_id
  listener_arn                   = local.service_common.listener_arn
  image_tag                      = local.service_common.image_tag
}

# ── wallet-web — THE WALLET ORIGIN ─────────────────────────────────────────────────────────
#
# Passkeys are created here and nowhere else. GIANO_RP_ID is this hostname and it is
# irreversible: every credential binds to it (spec §17 R1).
#
# The browser reaches wallet-api through nginx's same-origin /api proxy, which is what keeps
# sessions same-origin and avoids CORS. It reaches the RPC directly (the provider sends CORS
# headers) — note that this puts the provider API key in the browser, which is normal for a
# dev environment. To keep it server-side instead, set GIANO_RPC_UPSTREAM here and point the
# chain's rpcUrl at /rpc; the nginx template already carries that location.

module "wallet_web" {
  source = "../../modules/ecs-service"

  service_name       = "wallet-web"
  image_url          = module.ecr.repository_urls["wallet-web"]
  security_group_ids = [module.network.tasks_security_group_id]

  alb_host          = local.hosts.wallet
  listener_priority = 20
  health_check_path = "/"

  health_check_command = ["CMD-SHELL", "curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1"]

  environment = {
    GIANO_CHAIN_ID = tostring(var.chain_id)

    # Required by the entrypoint's single-chain branch even though sponsorship mode `service`
    # routes user operations through wallet-api rather than dialling the bundler directly.
    # If the wallet origin turns out to dial it, the bundler needs its own ALB target group and
    # hostname — spec §17 R3.
    GIANO_BUNDLER_URL = "https://${local.hosts.api}/v1/userops"

    GIANO_WALLET_API_UPSTREAM  = local.internal.wallet_api
    GIANO_ALLOWED_DAPP_ORIGINS = jsonencode(["https://${local.hosts.app}"])
    GIANO_RP_ID                = local.hosts.wallet
    GIANO_BRAND_NAME           = var.brand_name

    # The production paymaster through the ERC-7677 sponsorship service, not the permissive
    # test paymaster. Setting GIANO_PAYMASTER_ADDRESS here would silently select
    # `test-paymaster` instead — see the entrypoint's default.
    GIANO_SPONSORSHIP_MODE = var.sponsorship_enabled ? "service" : "off"

    # GIANO_CSP_CONNECT_SRC is left unset: the entrypoint defaults it to the RPC and bundler
    # URLs, which is exactly right and saves plumbing a secret's value into a template.
  }

  secrets = {
    GIANO_RPC_URL = local.rpc_url_arn
  }

  cluster_id                     = local.service_common.cluster_id
  cluster_name                   = local.service_common.cluster_name
  region                         = local.service_common.region
  vpc_id                         = local.service_common.vpc_id
  subnet_ids                     = local.service_common.subnet_ids
  execution_role_arn             = local.service_common.execution_role_arn
  service_discovery_namespace_id = local.service_common.service_discovery_namespace_id
  listener_arn                   = local.service_common.listener_arn
  image_tag                      = local.service_common.image_tag
}

# ── the demo dApp ──────────────────────────────────────────────────────────────────────────
#
# BLOCKED until services/custom-example gains a Dockerfile and runtime config (spec §15.1).
# It currently reads everything from import.meta.env.VITE_* at BUILD time, so these variables
# only take effect once it fetches /config.json the way wallet-web does. The names below are
# what that entrypoint should consume.

module "custom_example" {
  source = "../../modules/ecs-service"

  service_name       = "custom-example"
  image_url          = module.ecr.repository_urls["custom-example"]
  security_group_ids = [module.network.tasks_security_group_id]

  alb_host          = local.hosts.app
  listener_priority = 30
  health_check_path = "/"

  health_check_command = ["CMD-SHELL", "curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1"]

  environment = {
    GIANO_CHAIN_ID   = tostring(var.chain_id)
    GIANO_CHAIN_NAME = var.chain_name
    GIANO_WALLET_URL = "https://${local.hosts.wallet}"
    # Single-chain: the demo's config treats a chain B id of 0 as "not configured".
    GIANO_CHAIN_B_ID = "0"
    GIANO_APP_LABEL  = var.brand_name
    # No GIANO_TEST_ERC20: the devnet default address means nothing on Base Sepolia.
  }

  secrets = {
    GIANO_RPC_URL = local.rpc_url_arn
  }

  cluster_id                     = local.service_common.cluster_id
  cluster_name                   = local.service_common.cluster_name
  region                         = local.service_common.region
  vpc_id                         = local.service_common.vpc_id
  subnet_ids                     = local.service_common.subnet_ids
  execution_role_arn             = local.service_common.execution_role_arn
  service_discovery_namespace_id = local.service_common.service_discovery_namespace_id
  listener_arn                   = local.service_common.listener_arn
  image_tag                      = local.service_common.image_tag
}

# ── paymaster-admin ────────────────────────────────────────────────────────────────────────
#
# Reads the chain directly; needs neither the database nor wallet-api. It WRITES through an
# injected browser wallet, so whoever holds the paymaster's role-admin key is the only person
# who can change anything through it.

module "paymaster_admin" {
  source = "../../modules/ecs-service"

  service_name       = "paymaster-admin"
  image_url          = module.ecr.repository_urls["paymaster-admin"]
  security_group_ids = [module.network.tasks_security_group_id]

  alb_host          = local.hosts.paymaster
  listener_priority = 40
  health_check_path = "/"

  health_check_command = ["CMD-SHELL", "curl -fsS http://127.0.0.1:8080/ > /dev/null || exit 1"]

  environment = {
    GIANO_CHAIN_ID = tostring(var.chain_id)
    # Must be set explicitly: the contracts registry has no sponsorshipPaymaster for 84532.
    GIANO_PAYMASTER_ADDRESS = var.paymaster_address
    GIANO_ENVIRONMENT_LABEL = "${var.environment} (${var.chain_name})"
    GIANO_REFRESH_SECONDS   = "15"
  }

  secrets = {
    GIANO_RPC_URL = local.rpc_url_arn
  }

  cluster_id                     = local.service_common.cluster_id
  cluster_name                   = local.service_common.cluster_name
  region                         = local.service_common.region
  vpc_id                         = local.service_common.vpc_id
  subnet_ids                     = local.service_common.subnet_ids
  execution_role_arn             = local.service_common.execution_role_arn
  service_discovery_namespace_id = local.service_common.service_discovery_namespace_id
  listener_arn                   = local.service_common.listener_arn
  image_tag                      = local.service_common.image_tag
}

# ── bundler ────────────────────────────────────────────────────────────────────────────────
#
# No alb_host, therefore no target group and no listener rule: it is reachable only from the
# `tasks` security group, over Cloud Map. safe-mode is on because this is a real chain, and
# GIANO_DEV_MODE stays unset so the entrypoint's well-known-Anvil-key guard stays armed.

module "bundler" {
  source = "../../modules/ecs-service"

  service_name       = "bundler"
  image_url          = module.ecr.repository_urls["bundler"]
  cpu                = 512
  memory             = 1024
  container_port     = 4337
  security_group_ids = [module.network.bundler_security_group_id]

  alb_host = null

  health_check_command = [
    "CMD-SHELL",
    "curl -fsS -X POST -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_supportedEntryPoints\",\"params\":[]}' http://127.0.0.1:4337 || exit 1",
  ]

  environment = {
    ALTO_ENTRYPOINTS = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"
    ALTO_SAFE_MODE   = "true"
    ALTO_PORT        = "4337"
  }

  secrets = {
    ALTO_RPC_URL               = local.rpc_url_arn
    ALTO_EXECUTOR_PRIVATE_KEYS = aws_ssm_parameter.placeholder["alto-executor-key"].arn
    ALTO_UTILITY_PRIVATE_KEY   = aws_ssm_parameter.placeholder["alto-utility-key"].arn
  }

  cluster_id                     = local.service_common.cluster_id
  cluster_name                   = local.service_common.cluster_name
  region                         = local.service_common.region
  vpc_id                         = local.service_common.vpc_id
  subnet_ids                     = local.service_common.subnet_ids
  execution_role_arn             = local.service_common.execution_role_arn
  service_discovery_namespace_id = local.service_common.service_discovery_namespace_id
  listener_arn                   = local.service_common.listener_arn
  image_tag                      = local.service_common.image_tag
}

# ── scheduling and CI ──────────────────────────────────────────────────────────────────────

module "scheduler" {
  source = "../../modules/scheduler"

  name          = local.name
  enabled       = var.enable_schedule
  cluster_name  = module.cluster.cluster_name
  cluster_arn   = module.cluster.cluster_arn
  service_names = local.service_names
  up_cron       = var.schedule_up_cron
  down_cron     = var.schedule_down_cron
}

module "github_oidc" {
  source = "../../modules/github-oidc"

  name                 = local.name
  github_repository    = var.github_repository
  allowed_refs         = var.github_allowed_refs
  create_oidc_provider = var.create_github_oidc_provider

  cluster_arn  = module.cluster.cluster_arn
  cluster_name = module.cluster.cluster_name

  ecr_repository_arns = values(module.ecr.repository_arns)

  # Exactly the roles this environment's tasks run as. A wildcard here is the classic
  # privilege-escalation hole.
  passable_role_arns = [
    module.cluster.execution_role_arn,
    module.wallet_api.task_role_arn,
    module.wallet_web.task_role_arn,
    module.custom_example.task_role_arn,
    module.paymaster_admin.task_role_arn,
    module.bundler.task_role_arn,
    aws_iam_role.oneshot_task.arn,
  ]
}
