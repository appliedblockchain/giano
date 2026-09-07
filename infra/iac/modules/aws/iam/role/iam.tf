<<<<<<< HEAD
resource "aws_iam_role" "this" {
  name               = var.name
  assume_role_policy = var.assume_role_policy_json
=======
# A role, its trust policy and its attachments. §10

resource "aws_iam_role" "role" {
  name                 = var.name
  description          = var.description
  assume_role_policy   = var.assume_role_policy
  max_session_duration = var.max_session_duration
>>>>>>> main

  tags = merge(local.tags, { Name = var.name })
}

<<<<<<< HEAD
# aws_iam_role_policy has no `tags` argument — exempt per §4.3.1.
#
# No `count` gate on nullability here: both current callers (giano-dev-scheduler,
# giano-dev-gha-deploy) build this JSON from a `data "aws_iam_policy_document"` that itself
# references not-yet-created resources on a first apply (e.g. execution-role ARNs, the ECS
# cluster). That makes the STRING VALUE unknown at plan time, and comparing an unknown value
# against `null` for a `count` produces "Invalid count argument" — Terraform cannot prove the
# comparison is false even though it always is in practice. Always creating the resource
# sidesteps it entirely; `var.inline_policy_json` is therefore required, not optional.
resource "aws_iam_role_policy" "inline" {
  name   = "${var.name}-policy"
  role   = aws_iam_role.this.id
  policy = var.inline_policy_json
}

# aws_iam_role_policy_attachment has no `tags` argument — exempt per §4.3.1.
resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.this.name
=======
resource "aws_iam_role_policy" "inline" {
  for_each = var.inline_policies

  name   = "${var.name}-${each.key}"
  role   = aws_iam_role.role.id
  policy = each.value
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.role.name
>>>>>>> main
  policy_arn = each.value
}
