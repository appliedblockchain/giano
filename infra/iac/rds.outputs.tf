output "app_db" {
  description = "the application database's endpoint. The DSN itself is an ASM secret and is never output"
  value = {
    address    = module.app-db.address
    port       = module.app-db.port
    db_name    = local.app_db_name
    identifier = module.app-db.identifier
  }
}
