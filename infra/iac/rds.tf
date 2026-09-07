# §8.1 — one Postgres instance per environment.

module "app-db" {
  source = "./modules/aws/rds"

  name_prefix = local.name_prefix
  component   = "app"

  engine_version          = var.app-db-engine-version[terraform.workspace]
  instance_class          = var.app-db-instance-class[terraform.workspace]
  allocated_storage       = var.app-db-allocated-storage[terraform.workspace]
  storage_autoscale_max   = var.app-db-storage-autoscale-max[terraform.workspace]
  multi_az                = var.app-db-multi-az[terraform.workspace]
  backup_retention_period = var.app-db-backup-retention[terraform.workspace]
  deletion_protection     = var.app-db-deletion-protection[terraform.workspace]
  skip_final_snapshot     = var.app-db-skip-final-snapshot[terraform.workspace]

  db_name     = local.app_db_name
  db_username = var.db_username[terraform.workspace]

  # write-only — §8.3
  db_password_wo         = local.secret_values["database-password"]
  db_password_wo_version = local.secret_inventory["database-password"].version

  kms_key_id = aws_kms_key.rds-kms-key.arn

  vpc_id       = aws_vpc.vpc.id
  subnet_ids   = [aws_subnet.subnet-a-priv.id, aws_subnet.subnet-b-priv.id]
  source_sg_id = aws_security_group.tasks-sg.id

  additional_tags = local.default_tags
}
