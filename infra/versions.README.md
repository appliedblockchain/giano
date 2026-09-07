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

## ⚠️ Changing anything else in `infra/iac` does NOT deploy

The ECS services carry `ignore_changes = [task_definition]`, so `terraform apply` writes a new
task definition revision and leaves the running service on the old one. An env var, a CPU bump, a
rotated secret, a sidecar change — all apply successfully and **none of them take effect**.

After any such apply, run `deploy.yml` manually (Actions → Deploy → Run workflow) to roll the
services onto the revision you just wrote. R28 records why this is a convention rather than
something the apply does for you.
