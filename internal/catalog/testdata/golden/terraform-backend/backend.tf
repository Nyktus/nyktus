terraform {
  backend "http" {
    address        = "https://stateq3xwz7a2kfm4ub6tyc5nre.d.example.net/state/platform-prod"
    lock_address   = "https://stateq3xwz7a2kfm4ub6tyc5nre.d.example.net/state/platform-prod/lock"
    unlock_address = "https://stateq3xwz7a2kfm4ub6tyc5nre.d.example.net/state/platform-prod/lock"
    username       = "terraform"
    password       = "Xy7Xy7Xy7Xy7Xy7Xy7Xy7Xy7"
  }
}
