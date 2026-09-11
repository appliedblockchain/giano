locals {
  notifiers    = concat(["@slack-giano-alerts"], var.additional_notifiers)
  full_message = trimspace(join("\n", concat(var.message == "" ? [] : [var.message], local.notifiers)))

  # Datadog monitor tags are a flat list of "key:value" strings, not a map.
  tags_list = [for k, v in var.additional_tags : "${k}:${v}"]
}
