terraform {
  required_providers {
    kubectl = {
      source = "gavinbunney/kubectl"
      version = "1.14.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.57.0"
    }
    tls = {
      source = "hashicorp/tls"
      version = "4.0.5"
    }

    local = {
      source = "hashicorp/local"
      version = "2.5.1"
    }

    archive = {
      source = "hashicorp/archive"
      version = "2.4.2"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
  profile = "default"
  alias = "seoul"
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