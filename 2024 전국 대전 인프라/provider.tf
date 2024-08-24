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
provider "kubernetes" {
  host                   = aws_eks_cluster.skills.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.skills.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.skills.name]
    command     = "aws"
  }
}

provider "helm" {
  kubernetes {
    host                   = aws_eks_cluster.skills.endpoint
    cluster_ca_certificate = base64decode(aws_eks_cluster.skills.certificate_authority[0].data)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.skills.name]
      command     = "aws"
    }
  }
}

provider "kubectl" {
  host                   = aws_eks_cluster.skills.endpoint
  cluster_ca_certificate = base64decode(aws_eks_cluster.skills.certificate_authority[0].data)
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", aws_eks_cluster.skills.name]
    command     = "aws"
  }
}