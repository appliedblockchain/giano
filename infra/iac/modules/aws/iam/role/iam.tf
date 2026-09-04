# A role, its trust policy and its attachments. §10

resource "aws_iam_role" "role" {
  name                 = var.name
  description          = var.description
  assume_role_policy   = var.assume_role_policy
  max_session_duration = var.max_session_duration

  tags = merge(local.tags, { Name = var.name })
}

resource "aws_iam_role_policy" "inline" {
  for_each = var.inline_policies

  name   = "${var.name}-${each.key}"
  role   = aws_iam_role.role.id
  policy = each.value
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.role.name
  policy_arn = each.value
}
