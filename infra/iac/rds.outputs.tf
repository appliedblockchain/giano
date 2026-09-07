<<<<<<< HEAD
output "app_db_address" {
  value = module.app-db.address
}

output "app_db_identifier" {
  value = module.app-db.identifier
=======
output "app_db" {
  description = "the application database's endpoint. The DSN itself is an ASM secret and is never output"
  value = {
    address    = module.app-db.address
    port       = module.app-db.port
    db_name    = local.app_db_name
    identifier = module.app-db.identifier
  }
>>>>>>> main
}
