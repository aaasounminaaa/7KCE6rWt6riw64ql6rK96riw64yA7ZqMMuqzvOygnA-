locals {
  instance_type = "t3.large"
  cluster_name = "hrdkorea-cluster"
}

data "aws_caller_identity" "current" {}

resource "aws_eks_cluster" "skills" {
  name     = "${local.cluster_name}"
  role_arn = aws_iam_role.cluster.arn #"${var.cluster_role}"
  version = "1.29"
  vpc_config {
    subnet_ids = [
      aws_subnet.private_a.id, aws_subnet.private_b.id,
      aws_subnet.public_a.id, aws_subnet.public_b.id
    ]
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids = [ aws_security_group.control-plane.id ]
  }
  access_config {
    authentication_mode = "API_AND_CONFIG_MAP"
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.cluster-default,
    aws_iam_role_policy_attachment.vpc-resource-controller,
  ]
}

resource "aws_eks_access_entry" "root-allow" { #EKS 클러스터에 대한 액세스 항목 구성
  cluster_name  = aws_eks_cluster.skills.name
  principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "root-allow" { #EKS 클러스터에 대한 액세스 항목 정책 연결
  cluster_name  = aws_eks_cluster.skills.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = aws_eks_access_entry.root-allow.principal_arn

  access_scope {
    type = "cluster"
  }

  depends_on = [ aws_eks_access_entry.root-allow ]
}

resource "aws_eks_access_entry" "bastion-allow" { #EKS 클러스터에 대한 액세스 항목 구성
  cluster_name  = aws_eks_cluster.skills.name
  principal_arn = aws_iam_role.bastion.arn
  type          = "STANDARD"
  # depends_on = [
  #   aws_iam_role.bastion
  # ]
}

resource "aws_eks_access_policy_association" "root-allow-AmazonEKSAdminPolicy" { #EKS 클러스터에 대한 액세스 항목 정책 연결
  cluster_name  = aws_eks_cluster.skills.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"
  principal_arn = aws_eks_access_entry.bastion-allow.principal_arn

  access_scope {
    type = "cluster"
  }

  depends_on = [ aws_eks_access_entry.bastion-allow ]
}

resource "aws_eks_addon" "kube-proxy" {
  cluster_name = aws_eks_cluster.skills.name
  addon_name   = "kube-proxy"
  addon_version = "v1.29.3-eksbuild.5"
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.skills.name
  addon_name   = "coredns"
  addon_version = "v1.11.1-eksbuild.4"
  resolve_conflicts_on_update = "OVERWRITE"

  depends_on = [ aws_eks_node_group.order,aws_eks_node_group.customer,aws_eks_node_group.product ]
}

resource "aws_eks_addon" "vpc-cni" {
  cluster_name = aws_eks_cluster.skills.name
  addon_name   = "vpc-cni"
  addon_version = "v1.16.0-eksbuild.1"
  resolve_conflicts_on_update = "OVERWRITE"
}

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.skills.identity[0].oidc[0].issuer
  }

resource "aws_security_group" "control-plane" {
  name        = "control-plane-sg"
  description = "Allow HTTPS traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cluster.certificates[0].sha1_fingerprint]
  url             = data.tls_certificate.cluster.url
}

resource "random_string" "random_role" {
  length           = 5
  upper   = false
  lower   = false
  numeric  = true
  special = false
}

data "aws_iam_policy_document" "cluster" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "cluster" {
  name               = "eksClusterRole${random_string.random_role.result}"
  assume_role_policy = data.aws_iam_policy_document.cluster.json
}

resource "aws_iam_role_policy_attachment" "cluster-default" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.cluster.name
}

resource "aws_iam_role_policy_attachment" "vpc-resource-controller" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.cluster.name
}