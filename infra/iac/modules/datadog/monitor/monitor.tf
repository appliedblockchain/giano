# wraps datadog_monitor with thresholds and a notifier list — §17.3.5
#
# Child modules do not inherit a provider's SOURCE ADDRESS from the root, only its
# configuration — the datadog/datadog provider is outside the default hashicorp/ namespace,
# so this module must repeat the source here or Terraform assumes hashicorp/datadog and fails
# to resolve it.
terraform {
  required_providers {
    datadog = { source = "DataDog/datadog" }
  }
}

resource "datadog_monitor" "this" {
  name    = var.name
  type    = var.monitor_type
  query   = var.query
  message = local.full_message
  tags    = local.tags_list

  monitor_thresholds {
    critical = try(var.monitor_thresholds.critical, null)
    warning  = try(var.monitor_thresholds.warning, null)
    ok       = try(var.monitor_thresholds.ok, null)
  }

  notify_no_data    = var.notify_no_data
  no_data_timeframe = var.no_data_timeframe

  include_tags = true
}
