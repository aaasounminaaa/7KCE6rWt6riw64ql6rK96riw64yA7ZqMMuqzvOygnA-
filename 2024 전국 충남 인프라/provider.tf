terraform {
  required_providers {
    kubectl = {
      source = "gavinbunney/kubectl"
      version = "1.14.0"    
    }
    aws = {
      source  = "hashicorp/aws"
    }

    tls = {
      source = "hashicorp/tls"
      version = "4.0.4"
    }

    local = {
      source = "hashicorp/local"
      version = "2.4.0"
    }

    archive = {
      source = "hashicorp/archive"
      version = "2.4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  profile = "default"
  alias = "usa"
}

provider "tls" {
}

provider "local" {
}

provider "archive" {
}

data "aws_caller_identity" "caller" {
}