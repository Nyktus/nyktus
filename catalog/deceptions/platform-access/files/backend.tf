terraform {
  backend "http" {
    address        = "https://Honeytoken-Domain-State/state/platform-prod"
    lock_address   = "https://Honeytoken-Domain-State/state/platform-prod/lock"
    unlock_address = "https://Honeytoken-Domain-State/state/platform-prod/lock"
    username       = "ci-pull"
    password       = "Ajr4dJD1yVQbVLZIJS8Y1LAB"
  }
}
