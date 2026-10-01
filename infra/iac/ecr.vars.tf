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

# Counted in ECR images, not commits: the policy expires on `tagStatus: any`, so every manifest in a
# published list spends budget. Since ABIP-2 (docs/abip-compliance.md) a commit publishes about six —
# the index, two platform manifests, two attestation manifests (SBOM + provenance) and the cosign
# signature — where it published three. 30 keeps about five deployable commits, no fewer than the
# three that 10 kept, and the floor that matters is the pinned var.image_tag still being present.
variable "ecr_lifecycle_image_count" {
  description = "keep the last N images (manifests, not commits — about six per published commit)"
  type        = map(number)
  default     = { dev = 30, stg = 30, prd = 30 }
}
