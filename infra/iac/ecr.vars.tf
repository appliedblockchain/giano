# §11

variable "ecr_repos" {
  description = "one repository per deployed image — six for seven services, since custom-example and custom-example-byoui share giano-example"
  type        = list(string)
  default     = ["wallet-api", "wallet-web", "paymaster-admin", "example", "wallet-byo", "bundler"]
}

variable "ecr_image_tag_mutability" {
  description = "IMMUTABLE in every environment — a tag that can be repointed means the deployed artefact cannot be identified from the console"
  type        = map(string)
  default     = { dev = "IMMUTABLE", stg = "IMMUTABLE", prd = "IMMUTABLE" }
}

variable "ecr_lifecycle_image_count" {
  # A retention FLOOR under the tag infra/versions.json pins, not a cost knob: the policy counts
  # `tagStatus: any`, and each main push lands about six images per repository (two arches plus
  # SBOM/provenance attestations). At 10 that was under two commits, so on 2026-10-20 the
  # pinned dev image expired and every service failed to pull on the next scale-up. 120 is
  # about twenty commits between dev deploys. specs/CI-RELEASE-SPECS.md §7.2, O-6.
  description = "keep the last N images"
  type        = map(number)
  default     = { dev = 120, stg = 10, prd = 10 }
}
