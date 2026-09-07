output "secret_names" {
  description = "every secret this environment holds, by key. Names only — there is no output that returns a value"
  value = merge(
    module.asm-app.secret_names,
    {
      "database-url"    = aws_secretsmanager_secret.database-url.name
      "datadog-api-key" = aws_secretsmanager_secret.datadog-api-key.name
    },
  )
}

output "secret_inventory_versions" {
  description = "{ key => rotation version } as read from the 1Password note — the first thing to check when a rotation 'did not take' (R6)"
  value       = { for k, v in local.secret_inventory : k => v.version }
}
