locals {
  # Datadog has no provider-level default_tags, so a Datadog monitor is the
  # one place hand-merging the deployment's common tags is correct: nothing
  # else applies them. §4.3.1
  tags = [
    for k, v in merge(var.additional_tags, { module = "datadog/monitor" }) : "${k}:${v}"
  ]

  notifiers = distinct(concat(var.notifiers, var.additional_notifiers))

  # Datadog routes an alert by the handles in its message body.
  message = trimspace(join("\n\n", compact([var.message, join(" ", local.notifiers)])))
}
