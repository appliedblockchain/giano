# `versions.json` — the deployed version of each environment

**This file is the deployment.** Changing a value here and merging it to `main` is what rolls
an environment onto a new image; nothing else does. See `specs/INFRASTRUCTURE.md` §15.1.

```json
{ "dev": "<40-character commit sha>", "stg": "", "prd": "" }
```

The value is the **full** commit SHA that `docker.yml` tagged the images with — `git rev-parse`
of a commit whose build has finished, not necessarily the newest. `""` means an environment that
has never been deployed.

Two things read it, and they must not disagree:

| Reader | How |
|---|---|
| Terraform | `jsondecode(file(...))[terraform.workspace]` in `infra/iac/_locals.tf` — the image in every task definition it writes |
| `.github/workflows/deploy.yml` | `jq -r .dev infra/versions.json` — the image it rolls the services onto |

It is JSON rather than a `.tf` variable for exactly that reason: the workflow has to parse it
without Terraform, and grepping HCL is not parsing.

## Before you bump it

1. **The build must have finished.** `docker.yml` publishes on push to `main`; check the run for
   that SHA is green before naming it here, or the deploy fails pulling an image that does not
   exist yet.
2. **The tag must still exist.** ECR keeps the last `var.ecr_lifecycle_image_count` images per
   repository and counts `tagStatus: any`, so a SHA older than that many main-pushes has been
   expired. R27.

## Rolling back

Revert the change and merge. The rollback path is the deployment path.

## What `terraform apply` still does

Everything it did before. Terraform owns the task definitions and rolls the services onto them, so
an apply that changes an env var, a secret version, cpu or a sidecar takes effect the way it always
has — the services do **not** carry `ignore_changes = [task_definition]`, deliberately (§15.1).

Two writers therefore touch the same attribute, and they agree because they read the same value:
this file. Which means one thing to expect and not be alarmed by —

> The first `terraform apply` after a deploy shows **all seven task definitions being replaced and
> all seven services updating**. That is Terraform catching up to the revision the workflow already
> rolled out, at the same tag. It restarts the tasks and re-runs `wallet-api`'s migrations, which
> are tracked and idempotent.

And one thing to be careful about: **applying from a stale branch downgrades the environment.**
`local.image_tag` comes from this file in your working tree, so a branch cut before the last bump
deploys the older tag. Rebase before you apply.
