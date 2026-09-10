# standalone IAM policy documents that are not one-to-one with a resource elsewhere — §10.2,
# §17.2. The EventBridge Scheduler execution role: ecs:UpdateService on this cluster's
# services only, never on the whole account.

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

data "aws_iam_policy_document" "scheduler_update_service" {
  statement {
    sid     = "UpdateServiceDesiredCount"
    actions = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = [
      "arn:aws:ecs:${var.aws_region[terraform.workspace]}:${data.aws_caller_identity.current.account_id}:service/${aws_ecs_cluster.ecs.name}/*",
    ]
  }
}
