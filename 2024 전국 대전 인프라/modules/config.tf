terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
    }
    kubectl = {
      source = "gavinbunney/kubectl"
      version = "1.14.0"    
    }
  }
}

provider "aws" {
  alias  = "seoul"
  region = "ap-northeast-2"
}