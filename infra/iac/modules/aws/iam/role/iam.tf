resource "aws_iam_role" "this" {
  name               = var.name
  assume_role_policy = var.assume_role_policy_json

  tags = merge(local.tags, { Name = var.name })
}

# aws_iam_role_policy has no `tags` argument — exempt per §4.3.1.
resource "aws_iam_role_policy" "inline" {
  count = var.inline_policy_json == null ? 0 : 1

  name   = "${var.name}-policy"
  role   = aws_iam_role.this.id
  policy = var.inline_policy_json
}

# aws_iam_role_policy_attachment has no `tags` argument — exempt per §4.3.1.
resource "aws_iam_role_policy_attachment" "managed" {
  for_each = toset(var.managed_policy_arns)

  role       = aws_iam_role.this.name
  policy_arn = each.value
}
