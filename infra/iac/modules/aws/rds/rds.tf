<<<<<<< HEAD
# aws_db_instance, aws_db_subnet_group, aws_db_parameter_group — §8.1, §8.2, §8.3
#
# Fixed inside the module, not exposed as inputs, because varying them is never right (§8.1).

resource "aws_db_subnet_group" "db" {
  name       = "${var.name_prefix}-${var.component}-db-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(local.tags, { Name = "${var.name_prefix}-${var.component}-db-subnet-group" })
}

resource "aws_db_parameter_group" "db" {
  name   = "${var.name_prefix}-${var.component}-db-params"
=======
# One Postgres instance, its subnet group and its parameter group. §8
#
# Terraform creates the instance and NEVER the schema: migrations are owned by
# services/wallet-api/migrations and applied by the wallet-api task's init
# container (§9.6), so no application container ever starts against an
# un-migrated schema.

resource "aws_db_subnet_group" "db" {
  name       = "${local.name}-db-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(local.tags, { Name = "${local.name}-db-subnet-group" })
}

resource "aws_db_parameter_group" "db" {
  name   = "${local.name}-db-parameter-group"
>>>>>>> main
  family = local.parameter_group_family

  parameter {
    name  = "log_min_duration_statement"
<<<<<<< HEAD
    value = "1000" # anything over a second lands in the logs
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-${var.component}-db-params" })
}

resource "aws_db_instance" "db" {
  identifier     = "${var.name_prefix}-${var.component}-db"
=======
    value = tostring(var.log_min_duration_statement)
  }

  tags = merge(local.tags, { Name = "${local.name}-db-parameter-group" })

  lifecycle { create_before_destroy = true }
}

resource "aws_db_instance" "db" {
  identifier = "${local.name}-db"

>>>>>>> main
  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.storage_autoscale_max
<<<<<<< HEAD
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_id

  db_name             = var.db_name
  username            = var.db_username
  password_wo         = var.db_password_wo
  password_wo_version = var.db_password_wo_version
  port                = 5432
=======

  db_name  = var.db_name
  username = var.db_username

  # Write-only. The password is hand-authored in the 1Password bundle and
  # reaches the instance without ever entering state. `random_password` is the
  # obvious alternative and is rejected: its result sits in state, in
  # plaintext, forever — and "no secrets in state except the one that opens
  # the database" is not a guarantee. §8.3
  password_wo         = var.db_password_wo
  password_wo_version = var.db_password_wo_version

  multi_az                = var.multi_az
  backup_retention_period = var.backup_retention_period
  deletion_protection     = var.deletion_protection
  skip_final_snapshot     = var.skip_final_snapshot
  # A fixed name, not one built from timestamp(): a timestamp in an argument
  # is a diff on every plan.
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${local.name}-db-final-snapshot"
>>>>>>> main

  db_subnet_group_name   = aws_db_subnet_group.db.name
  parameter_group_name   = aws_db_parameter_group.db.name
  vpc_security_group_ids = [aws_security_group.db-sg.id]

<<<<<<< HEAD
  multi_az                            = var.multi_az
  publicly_accessible                 = false
=======
  kms_key_id        = var.kms_key_id
  storage_encrypted = true

  # Fixed here rather than exposed as inputs, because varying them is never
  # right. §8.1
  publicly_accessible                 = false
  storage_type                        = "gp3"
  port                                = 5432
>>>>>>> main
  copy_tags_to_snapshot               = true
  auto_minor_version_upgrade          = true
  iam_database_authentication_enabled = false
  ca_cert_identifier                  = "rds-ca-rsa4096-g1"
  maintenance_window                  = "tue:02:00-tue:02:30"

<<<<<<< HEAD
  backup_retention_period   = var.backup_retention_period
  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.name_prefix}-${var.component}-db-final"

  # a restore-from-snapshot performed out of band must not be reverted by the next apply — §8.3
  lifecycle {
    ignore_changes = [snapshot_identifier]
  }

  tags = merge(local.tags, { Name = "${var.name_prefix}-${var.component}-db" })
=======
  tags = merge(local.tags, { Name = "${local.name}-db" })

  lifecycle {
    # A restore-from-snapshot performed out of band is not reverted by the
    # next apply. §8.3
    ignore_changes = [snapshot_identifier]
  }
>>>>>>> main
}
