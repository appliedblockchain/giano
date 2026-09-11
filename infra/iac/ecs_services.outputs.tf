output "ecs_services" {
  description = "{ service => task definition family } — for the deploy workflow's update-service loop (§15)"
  value = merge(
    { wallet-api = module.svc-wallet-api.task_definition_family },
    { wallet-web = module.svc-wallet-web.task_definition_family },
    { custom-example = module.svc-custom-example.task_definition_family },
    { paymaster-admin = module.svc-paymaster-admin.task_definition_family },
    { bundler = module.svc-bundler.task_definition_family },
    length(module.svc-custom-example-byoui) > 0 ? { custom-example-byoui = module.svc-custom-example-byoui[0].task_definition_family } : {},
    length(module.svc-wallet-byo) > 0 ? { wallet-byo = module.svc-wallet-byo[0].task_definition_family } : {},
  )
}
