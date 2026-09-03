# One task definition with NO service attached, run by `aws ecs run-task`
# using the RUN_TASK_NETWORK output. §9.7
#
# provision-sponsorship installs a tenant's sponsorship rules through the real
# admin API. Run once at bring-up PER TENANT and whenever the rules change —
# a tenant with no rules is refused every transaction, which looks exactly
# like a bug.
#
# It is not an init container because it is not a precondition of anything
# starting: it is an occasional administrative action against a RUNNING API,
# and running it on every task start would re-PUT the same rules a dozen times
# a day for no reason. Blocked on §16.3.

resource "aws_ecs_task_definition" "provision-sponsorship" {
  family = "${local.name_prefix}-provision-sponsorship"

  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  execution_role_arn = module.provision-sponsorship-exec-role.arn
  task_role_arn      = module.provision-sponsorship-task-role.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([{
    # The container name the runbook's --overrides addresses. Do not rename it
    # without changing §18 step 8.
    name  = "provision-sponsorship"
    image = "${module.ecr["wallet-api"].repository_url}:${var.image_tag}"

    command   = var.provision_sponsorship_command
    essential = true

    environment = [
      # Reached over Cloud Map rather than the public hostname: the tenant is
      # selected by TENANT_SLUG and the admin key, not by the Host header, so
      # there is nothing to gain from an internet round-trip.
      { name = "WALLET_API_URL", value = local.upstream_wallet_api },
      { name = "CHAIN_ID", value = local.chain_id },
      { name = "SPONSORSHIP_PAYMASTER_ADDRESS", value = var.paymaster_address[terraform.workspace] },

      # Overridden per run — one invocation per tenant.
      { name = "TENANT_SLUG", value = "" },
    ]

    secrets = [
      # Carries the tenants' adminKeys.
      { name = "TENANTS_SEED", valueFrom = module.asm-app.secret_arns["tenants-seed"] },
    ]

    # Plain awslogs, not FireLens: a task that lives forty seconds can exit
    # before Fluent Bit has flushed its buffer. §9.5
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.provision-sponsorship.name
        "awslogs-region"        = var.aws_region[terraform.workspace]
        "awslogs-stream-prefix" = "ecs"
      }
    }
  }])

  tags = { Name = "${local.name_prefix}-provision-sponsorship" }
}

module "provision-sponsorship-exec-role" {
  source = "./modules/aws/iam/role"

  name               = "${local.name_prefix}-provision-sponsorship-exec"
  description        = "${local.name_prefix} provision-sponsorship — image pull, log stream, secret resolution"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json

  inline_policies = { "policy" = data.aws_iam_policy_document.provision-sponsorship-exec.json }
}

module "provision-sponsorship-task-role" {
  source = "./modules/aws/iam/role"

  name               = "${local.name_prefix}-provision-sponsorship-task"
  description        = "${local.name_prefix} provision-sponsorship — the job's own runtime role, empty by design"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume.json
}
