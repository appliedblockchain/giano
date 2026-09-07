output "iam_roles" {
  description = "the roles that belong to no single service"
  value = {
    scheduler                  = module.scheduler-role.arn
    gha_deploy                 = module.gha-deploy-role.arn
    provision_sponsorship_exec = module.provision-sponsorship-exec-role.arn
    provision_sponsorship_task = module.provision-sponsorship-task-role.arn
  }
}
