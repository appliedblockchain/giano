output "datadog_monitor_ids" {
  description = "the monitors created for this environment, by name"
  value = merge(
    { for k, m in module.datadog_monitor_service_task_count : "task-count-${k}" => m.id },
    { for k, m in module.datadog_monitor_service_no_metrics : "no-metrics-${k}" => m.id },
    { for k, m in module.datadog_monitor_chain_balance : "chain-balance-${k}" => m.id },
    length(module.datadog_monitor_wallet_api_healthy_hosts) > 0 ? {
      "wallet-api-healthy-hosts" = module.datadog_monitor_wallet_api_healthy_hosts[0].id
    } : {},
    length(module.datadog_monitor_certificate_expiry) > 0 ? {
      "certificate-expiry" = module.datadog_monitor_certificate_expiry[0].id
    } : {},
  )
}
