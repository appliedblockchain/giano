provider "aws" {
  region = var.region

  # Applied through the provider so no resource can be created untagged. `Environment` is the
  # discriminator a staging root module varies; nothing inside a module hardcodes "dev".
  default_tags {
    tags = {
      Project     = "giano"
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "appliedblockchain/giano"
    }
  }
}
