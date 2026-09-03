locals {
  tags = merge(var.additional_tags, {
    module = "aws/ecs-service"
  })

  name = "${var.name_prefix}-${var.service}"

  # --- Container plumbing -------------------------------------------------

  # Sorted, so a map reordering is not a task-definition revision.
  environment = [
    for k in sort(keys(var.environment)) : { name = k, value = var.environment[k] }
  ]

  secrets = [
    for k in sort(keys(var.secret_arns)) : { name = k, valueFrom = var.secret_arns[k] }
  ]

  init_secrets = var.init_container == null ? [] : [
    for k in sort(keys(var.init_container.secrets)) : { name = k, valueFrom = var.init_container.secrets[k] }
  ]

  # Every secret ARN any container in this task resolves, plus the Datadog key
  # the sidecars need. Built from the same maps that produced the `secrets`
  # blocks, so the execution-role policy and the task definition cannot drift.
  # §10.2
  all_secret_arns = distinct(concat(
    values(var.secret_arns),
    var.init_container == null ? [] : values(var.init_container.secrets),
    var.datadog_enabled ? [var.datadog_api_key_arn] : [],
  ))

  # The application waits on the log router coming up so it never writes into
  # a router that has not started, and — where there is one — on the init
  # container exiting 0.
  #
  # condition = "SUCCESS" is the whole mechanism: COMPLETE would accept any
  # exit code and start the application against a half-applied schema, START
  # would not wait at all. §9.6
  app_depends_on = concat(
    var.datadog_enabled ? [{ containerName = "log_router", condition = "START" }] : [],
    var.init_container == null ? [] : [{ containerName = var.init_container.name, condition = "SUCCESS" }],
  )

  app_container = merge(
    {
      name         = var.service
      image        = var.image
      essential    = true
      memory       = var.app_memory
      portMappings = [{ containerPort = var.container_port, protocol = "tcp" }]
      environment  = local.environment
      secrets      = local.secrets

      logConfiguration = local.app_log_configuration
    },
    length(local.app_depends_on) > 0 ? { dependsOn = local.app_depends_on } : {},
  )

  init_container = var.init_container == null ? null : merge(
    {
      name    = var.init_container.name
      image   = var.image # the SAME image as the app — one artefact, two commands
      command = var.init_container.command

      # MANDATORY. An essential container exiting — even with 0 — stops the
      # whole task, so an init container that is essential turns every
      # successful migration into a failed deployment.
      essential = false

      # No hard `memory` limit: it runs before the application container, so
      # it can use the task's headroom, and its reservation is released the
      # moment it exits.
      memoryReservation = 256

      secrets     = local.init_secrets
      environment = [{ name = "LOG_LEVEL", value = "info" }]

      logConfiguration = local.app_log_configuration
    },
    var.datadog_enabled ? { dependsOn = [{ containerName = "log_router", condition = "START" }] } : {},
  )

  # slice() rather than a conditional: the container definitions are objects
  # with different attribute sets, and Terraform unifies the branches of a
  # conditional — which for two tuples of different lengths it cannot do.
  # slice keeps one element type per call and concat joins them untouched.
  container_definitions = concat(
    [local.app_container],
    slice([local.init_container], 0, local.init_container == null ? 0 : 1),
    slice([local.datadog_agent_container, local.firelens_container], 0, var.datadog_enabled ? 2 : 0),
  )

  # --- Deployment ---------------------------------------------------------

  deployment_minimum_healthy_percent = coalesce(
    var.deployment_minimum_healthy_percent, var.alb_enabled ? 100 : 0,
  )

  deployment_maximum_percent = coalesce(
    var.deployment_maximum_percent, var.alb_enabled ? 200 : 100,
  )

  # --- ALB ----------------------------------------------------------------

  # An ALB host condition accepts at most five values. Past that, additional
  # rules at descending priority against the same target group. §5.7
  alb_host_chunks = var.alb_enabled ? { for i, hosts in chunklist(var.alb_host_headers, 5) : i => hosts } : {}
}
