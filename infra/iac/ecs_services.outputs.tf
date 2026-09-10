output "ecs_service_names" {
  description = "{ service => ECS service name } — what the deploy workflow calls update-service on"
  value = merge(
    {
      "wallet-api"      = module.svc-wallet-api.service_name
      "wallet-web"      = module.svc-wallet-web.service_name
      "custom-example"  = module.svc-custom-example.service_name
      "paymaster-admin" = module.svc-paymaster-admin.service_name
      "bundler"         = module.svc-bundler.service_name
    },
    var.byo_wallet_enabled[terraform.workspace] ? {
      "custom-example-byoui" = module.svc-custom-example-byoui[0].service_name
      "wallet-byo"           = module.svc-wallet-byo[0].service_name
    } : {},
  )
}

output "ecs_task_role_arns" {
  description = "{ service => task role ARN } — CI needs iam:PassRole on these and on the execution roles, and on nothing else"
  value = merge(
    {
      "wallet-api"      = module.svc-wallet-api.task_role_arn
      "wallet-web"      = module.svc-wallet-web.task_role_arn
      "custom-example"  = module.svc-custom-example.task_role_arn
      "paymaster-admin" = module.svc-paymaster-admin.task_role_arn
      "bundler"         = module.svc-bundler.task_role_arn
    },
    var.byo_wallet_enabled[terraform.workspace] ? {
      "custom-example-byoui" = module.svc-custom-example-byoui[0].task_role_arn
      "wallet-byo"           = module.svc-wallet-byo[0].task_role_arn
    } : {},
  )
}
