# The seven services. §9.2, and §14 for the environment poured into them.
#
# Five of the seven are the same module with different inputs; the two that
# look like duplicates are not:
#
#   custom-example-byoui is the SAME image as custom-example with a different
#   GIANO_WALLET_URL — that one value is the entire difference between the two
#   dApps, and each dApp is pinned to exactly one wallet origin so the popup's
#   origin check means something.
#
#   wallet-byo is the only service Giano would not run in a real deployment: a
#   real BYO tenant hosts its own UI. It is here so the BYO serving contract
#   is exercised rather than described (D17).

locals {
  # Cloud Map hostnames. These replace compose's service names.
  upstream_wallet_api = "http://wallet-api.${local.service_discovery_namespace}:${var.container_port}"
  upstream_bundler    = "http://bundler.${local.service_discovery_namespace}:${var.bundler_port}"

  chain_id   = tostring(var.chain_id[terraform.workspace])
  chain_name = var.chain_name[terraform.workspace]

  # Common to every service instance below. Collected here so a change to the
  # observability path or the network is one edit rather than seven.
  service_defaults = {
    cluster_arn  = aws_ecs_cluster.ecs.arn
    cluster_name = aws_ecs_cluster.ecs.name
    aws_region   = var.aws_region[terraform.workspace]
    account_id   = data.aws_caller_identity.current.account_id
    project_name = var.project_name
  }
}

# --- wallet-api -----------------------------------------------------------
#
# The only service with database access, and the only one carrying an init
# container. Single-chain shorthand rather than GIANO_CHAINS — one chain is
# served, and the two shapes are mutually exclusive by design.

module "svc-wallet-api" {
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "wallet-api"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["wallet-api"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["wallet-api"].repository_arn

  cpu            = 512
  memory         = 2048 # app 1024 + agent 256 + router 100 + migrate 256 + headroom
  app_memory     = 1024 # Fastify + the viem clients + the paymaster watcher
  container_port = var.container_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.tasks-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    # `testnet` is the honest deployment class and it is what makes a `local`
    # sponsorship signer legal. §10.4, R14
    GIANO_DEPLOYMENT_CLASS = "testnet"

    # false: the init container runs them, and both trying is how two
    # containers in one task race for an advisory lock. §8.4
    RUN_MIGRATIONS = "false"

    CHAIN_ID    = local.chain_id
    BUNDLER_URL = local.upstream_bundler

    SPONSORSHIP_ENABLED           = "true"
    SPONSORSHIP_SIGNER_KIND       = "local"
    SPONSORSHIP_PAYMASTER_ADDRESS = var.paymaster_address[terraform.workspace]
    PAYMASTER_WATCHER_ENABLED     = "true"

    LOG_LEVEL = "info"

    # ENTRYPOINT_ADDRESS and FACTORY_ADDRESS are deliberately unset: the chain
    # is in the contracts registry and they default correctly from it. Setting
    # them by hand is how they drift. §14.2
  }

  secret_arns = {
    DATABASE_URL               = aws_secretsmanager_secret.database-url.arn
    RPC_URL                    = module.asm-app.secret_arns["rpc-url"]
    SPONSORSHIP_SIGNER_KEY_REF = module.asm-app.secret_arns["sponsorship-signer-key"]
    TENANTS_SEED               = module.asm-app.secret_arns["tenants-seed"]
    METRICS_BEARER_TOKEN       = module.asm-app.secret_arns["metrics-bearer-token"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  # No wallet-api container ever starts against an un-migrated schema — a
  # guarantee ECS enforces rather than one a pipeline produces. §9.6
  init_container = {
    name    = "migrate"
    command = ["node", "dist/migrate.js"]
    secrets = { DATABASE_URL = aws_secretsmanager_secret.database-url.arn }
  }

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 10
  alb_host_headers  = [local.hosts.api]
  health_check_path = "/healthz"

  # Must outlast the slowest expected migration. R22
  health_check_grace_period_seconds = 120

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["wallet-api"].datadog_source

  additional_tags = { service = "wallet-api" }
}

# --- wallet-web -----------------------------------------------------------
#
# ONE task serves every stock-UI tenant hostname. GIANO_RP_ID is deliberately
# UNSET so the SPA takes its RP ID from window.location.hostname — that is the
# mechanism the whole CNAME model rests on, and setting it would pin every
# tenant to one RP ID and break the model. §3.4

module "svc-wallet-web" {
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "wallet-web"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["wallet-web"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["wallet-web"].repository_arn

  cpu            = 256
  memory         = 1024
  app_memory     = 512
  container_port = var.container_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.tasks-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    GIANO_CHAIN_ID = local.chain_id

    # Required by the entrypoint's shorthand branch even though sponsorship
    # mode `service` relays user operations through wallet-api. R3 — if the
    # browser turns out to dial this directly, the bundler needs an ALB target
    # and a hostname of its own.
    GIANO_BUNDLER_URL = "https://${local.hosts.api}/v1/userops"

    # Same-origin /api and /.well-known/webauthn. nginx forwards Host and
    # Origin untouched, which is what lets wallet-api resolve the tenant per
    # request rather than per container. §3.3
    GIANO_WALLET_API_UPSTREAM = local.upstream_wallet_api

    GIANO_SPONSORSHIP_MODE = "service"
    GIANO_CSP_CONNECT_SRC  = var.rpc_origin[terraform.workspace]

    # These two are per TENANT but reach the SPA per CONTAINER, from
    # /config.json. A set of one here, not a union: only `example` is served
    # by this task. They leave this table when §16.4 lands, and until it does,
    # the rule to hold is one STOCK-UI tenant per wallet-web task. R9
    GIANO_ALLOWED_DAPP_ORIGINS = jsonencode(["https://${local.tenant_hosts.example.dapp}"])
    GIANO_BRAND_NAME           = "Giano Example"
  }

  secret_arns = {
    GIANO_RPC_URL = module.asm-app.secret_arns["rpc-url"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 40
  health_check_path = "/"

  # Giano's own serving hostname plus every stock-UI tenant host. This is the
  # rule that grows, and it is placed LAST so the ordering stays correct if
  # anyone later broadens the wallet condition. §5.7
  alb_host_headers = local.wallet_web_hosts

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["wallet-web"].datadog_source

  additional_tags = { service = "wallet-web" }
}

# --- custom-example, tenant `example`'s dApp ------------------------------
#
# Blocked on §16.1: the demo needs a Dockerfile and a runtime /config.json,
# or a naive build bakes dev hostnames into the image.

module "svc-custom-example" {
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "custom-example"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["example"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["example"].repository_arn

  cpu            = 256
  memory         = 1024
  app_memory     = 512
  container_port = var.container_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.tasks-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    GIANO_CHAIN_ID   = local.chain_id
    GIANO_CHAIN_NAME = local.chain_name
    GIANO_CHAIN_B_ID = "0" # single-chain; the config explicitly supports this

    # The TENANT's wallet hostname. Pointing this at Giano's serving hostname
    # is the one-character mistake that binds passkeys to infrastructure.
    # §18 step 10 checks it.
    GIANO_WALLET_URL = "https://${local.tenant_hosts.example.wallet}"
    GIANO_APP_LABEL  = "Giano Example"

    # GIANO_TEST_ERC20 unset: the devnet default address is meaningless here.
  }

  secret_arns = {
    GIANO_RPC_URL = module.asm-app.secret_arns["rpc-url"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 20
  alb_host_headers  = [local.tenant_hosts.example.dapp]
  health_check_path = "/"

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["custom-example"].datadog_source

  additional_tags = { service = "custom-example", tenant = "example" }
}

# --- custom-example-byoui, tenant `byoui`'s dApp --------------------------
#
# The same image and the same module as above. Two values differ, and they are
# the whole reason a second instance exists rather than a wallet picker in the
# UI. §14.4

module "svc-custom-example-byoui" {
  count  = var.byo_wallet_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "custom-example-byoui"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["example"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["example"].repository_arn

  cpu            = 256
  memory         = 1024
  app_memory     = 512
  container_port = var.container_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.tasks-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    GIANO_CHAIN_ID   = local.chain_id
    GIANO_CHAIN_NAME = local.chain_name
    GIANO_CHAIN_B_ID = "0"

    GIANO_WALLET_URL = "https://${local.tenant_hosts.byoui.wallet}"
    GIANO_APP_LABEL  = "Giano Example (BYO UI)"
  }

  secret_arns = {
    GIANO_RPC_URL = module.asm-app.secret_arns["rpc-url"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 25
  alb_host_headers  = [local.tenant_hosts.byoui.dapp]
  health_check_path = "/"

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["custom-example-byoui"].datadog_source

  additional_tags = { service = "custom-example-byoui", tenant = "byoui" }
}

# --- wallet-byo, tenant `byoui`'s wallet origin ---------------------------
#
# The framework-free SPA in e2e/wallet-byo, bundled with esbuild at container
# start, reverse-proxying the same paths wallet-web's nginx does. Blocked on
# §16.5 — and its /bundler proxy MUST NOT be reachable (R11): deployed as-is
# it is a public unauthenticated bundler relay that bypasses wallet-api's
# policy check and drains the Alto executor. Runbook step 13 verifies it.

module "svc-wallet-byo" {
  count  = var.byo_wallet_enabled[terraform.workspace] ? 1 : 0
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "wallet-byo"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["wallet-byo"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["wallet-byo"].repository_arn

  cpu            = 256
  memory         = 1024
  app_memory     = 512
  container_port = var.container_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.tasks-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    BYO_WALLET_PORT     = tostring(var.container_port)
    WALLET_API_UPSTREAM = local.upstream_wallet_api
    CHAIN_ID            = local.chain_id

    # The real sponsorship path, through /api/v1/paymaster. `service` mode
    # needs no bundler proxy and no permissive paymaster fixture, so
    # PAYMASTER_ADDRESS stays unset.
    SPONSORSHIP_MODE = "service"

    # BUNDLER_UPSTREAM is deliberately ABSENT and the proxy explicitly off.
    # This task sits in the tasks security group, which the bundler group
    # accepts on 4337 — so a live /bundler location here is an open relay on a
    # wallet origin. §16.5 must make the proxy disableable and honour this
    # flag; until it does, this service must not be deployed. R11
    BYO_BUNDLER_PROXY_ENABLED = "false"

    # This tenant's OWN allowlist, shipped with its own SPA — which is why R9
    # does not reach it, and why it can be tenant two today.
    BYO_ALLOWED_DAPP_ORIGINS = jsonencode(["https://${local.tenant_hosts.byoui.dapp}"])

    # CHAIN_B_ID and FACTORY_ADDRESS unset: single-chain, and the factory
    # defaults from the contracts registry.
  }

  secret_arns = {
    # Proxied same-origin, so the API key stays server-side.
    RPC_UPSTREAM = module.asm-app.secret_arns["rpc-url"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled      = true
  alb_listener_arn = aws_lb_listener.https.arn

  # ABOVE rule 40, deliberately: a broadened wallet condition would otherwise
  # capture this host and serve byoui the stock UI, which fails closed at the
  # popup handshake and looks like a tenancy bug rather than a routing one.
  alb_rule_priority = 35
  alb_host_headers  = [local.tenant_hosts.byoui.wallet]
  health_check_path = "/"

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["wallet-byo"].datadog_source

  additional_tags = { service = "wallet-byo", tenant = "byoui" }
}

# --- paymaster-admin ------------------------------------------------------
#
# Reads the chain directly and needs neither the database nor wallet-api. The
# console WRITES through an injected browser wallet, so whoever holds the
# role-admin key from §13.1 is the only person who can change anything.

module "svc-paymaster-admin" {
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "paymaster-admin"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["paymaster-admin"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["paymaster-admin"].repository_arn

  cpu            = 256
  memory         = 1024
  app_memory     = 512
  container_port = var.container_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.tasks-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    GIANO_CHAIN_ID = local.chain_id

    # Must be set — the registry has no paymaster entry for this chain. §13.1
    GIANO_PAYMASTER_ADDRESS = var.paymaster_address[terraform.workspace]

    GIANO_ENVIRONMENT_LABEL = "${terraform.workspace} (${local.chain_name})"
    GIANO_REFRESH_SECONDS   = "15"
  }

  secret_arns = {
    GIANO_RPC_URL = module.asm-app.secret_arns["rpc-url"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled       = true
  alb_listener_arn  = aws_lb_listener.https.arn
  alb_rule_priority = 30
  alb_host_headers  = [local.hosts.paymaster]
  health_check_path = "/"

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["paymaster-admin"].datadog_source

  additional_tags = { service = "paymaster-admin" }
}

# --- bundler --------------------------------------------------------------
#
# No target group, no listener rule, no hostname: alb_enabled = false. It is
# reachable only from the tasks security group, and wallet-api relays user
# operations to it after the policy check. §3.4

module "svc-bundler" {
  source = "./modules/aws/ecs-service"

  name_prefix = local.name_prefix
  service     = "bundler"

  cluster_arn  = local.service_defaults.cluster_arn
  cluster_name = local.service_defaults.cluster_name
  aws_region   = local.service_defaults.aws_region
  account_id   = local.service_defaults.account_id
  project_name = local.service_defaults.project_name

  image              = "${module.ecr["bundler"].repository_url}:${var.image_tag}"
  image_tag          = var.image_tag
  ecr_repository_arn = module.ecr["bundler"].repository_arn

  cpu            = 512
  memory         = 2048
  app_memory     = 1024
  container_port = var.bundler_port
  desired_count  = var.ecs_desired_count[terraform.workspace]

  vpc_id                         = aws_vpc.vpc.id
  subnet_ids                     = local.private_subnet_ids
  security_group_ids             = [aws_security_group.bundler-sg.id]
  service_discovery_namespace_id = aws_service_discovery_private_dns_namespace.ns.id

  environment = {
    ALTO_ENTRYPOINTS = var.entrypoint_address
    ALTO_SAFE_MODE   = "true" # this is a real chain

    # GIANO_DEV_MODE unset: the entrypoint's Anvil-key guard stays armed.
  }

  secret_arns = {
    ALTO_RPC_URL               = module.asm-app.secret_arns["rpc-url"]
    ALTO_EXECUTOR_PRIVATE_KEYS = module.asm-app.secret_arns["alto-executor-key"]
    ALTO_UTILITY_PRIVATE_KEY   = module.asm-app.secret_arns["alto-utility-key"]
  }

  asm_kms_key_arn = aws_kms_key.asm-kms-key.arn

  alb_enabled = false

  enable_execute_command = var.ecs_enable_execute_command[terraform.workspace]
  wait_for_steady_state  = var.ecs_wait_for_steady_state
  log_retention_in_days  = var.log_retention_in_days[terraform.workspace]

  datadog_enabled     = var.datadog_enabled[terraform.workspace]
  datadog_site        = var.datadog_site
  datadog_api_key_arn = aws_secretsmanager_secret.datadog-api-key.arn
  datadog_source      = local.ecs_services["bundler"].datadog_source

  additional_tags = { service = "bundler" }
}
