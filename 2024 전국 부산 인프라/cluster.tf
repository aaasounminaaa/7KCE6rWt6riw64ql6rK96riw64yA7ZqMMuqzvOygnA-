locals {
  instance_type = "t3.medium"
  cluster_name = "wsi-cluster"
}

data "aws_caller_identity" "current" {}

# resource "aws_kms_key" "example" {
#   description             = "An example symmetric encryption KMS key"
#   enable_key_rotation     = true
#   deletion_window_in_days = 20
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Id      = "key-default-1"
#     Statement = [
#       {
#         Sid    = "Enable IAM User Permissions"
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
#         },
#         Action   = "kms:*"
#         Resource = "*"
#       },
#       {
#         Sid    = "Allow administration of the key"
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/admin"
#         },
#         Action = [
#           "kms:ReplicateKey",
#           "kms:Create*",
#           "kms:Describe*",
#           "kms:Enable*",
#           "kms:List*",
#           "kms:Put*",
#           "kms:Update*",
#           "kms:Revoke*",
#           "kms:Disable*",
#           "kms:Get*",
#           "kms:Delete*",
#           "kms:ScheduleKeyDeletion",
#           "kms:CancelKeyDeletion"
#         ],
#         Resource = "*"
#       },
#       {
#         Sid    = "Allow use of the key"
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/admin"
#         },
#         Action = [
#           "kms:DescribeKey",
#           "kms:Encrypt",
#           "kms:Decrypt",
#           "kms:ReEncrypt*",
#           "kms:GenerateDataKey",
#           "kms:GenerateDataKeyWithoutPlaintext"
#         ],
#         Resource = "*"
#       }
#     ]
#   })
# }

resource "aws_eks_cluster" "skills" {
  name     = "${local.cluster_name}"
  version = "1.29"
  role_arn = aws_iam_role.cluster.arn #"${var.cluster_role}"
  vpc_config {
    subnet_ids = [
      aws_subnet.private_a.id, aws_subnet.private_b.id,aws_subnet.private_c.id

    ]
    endpoint_private_access = false
    endpoint_public_access  = true
    # security_group_ids = [ aws_security_group.control-plane.id ]
  }
#   encryption_config {
#     provider {
#       key_arn = aws_kms_key.example.arn
#     }
#     resources = ["secrets"]
#   }
  access_config {
    authentication_mode = "API_AND_CONFIG_MAP"
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  depends_on = [
    aws_iam_role_policy_attachment.cluster-default,
    aws_iam_role_policy_attachment.vpc-resource-controller,
  ]
  lifecycle {
    create_before_destroy = true
  }
}

# resource "aws_eks_access_entry" "bastion-allow" { #EKS 클러스터에 대한 액세스 항목 구성
#   cluster_name  = aws_eks_cluster.skills.name
#   principal_arn = aws_iam_role.bastion.arn
#   type          = "STANDARD"
  # depends_on = [
  #   aws_iam_role.bastion
  # ]
#}

# resource "aws_eks_access_policy_association" "root-allow" { #EKS 클러스터에 대한 액세스 항목 정책 연결
#   cluster_name  = aws_eks_cluster.skills.name
#   policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
#   principal_arn = aws_eks_access_entry.bastion-allow.principal_arn

#   access_scope {
#     type = "cluster"
#   }

#   depends_on = [ aws_eks_access_entry.bastion-allow ]
# }

resource "aws_eks_access_policy_association" "root-allow-AmazonEKSAdminPolicy" { #EKS 클러스터에 대한 액세스 항목 정책 연결
  cluster_name  = aws_eks_cluster.skills.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAdminPolicy"
  principal_arn = aws_eks_access_entry.console-allow.principal_arn

  access_scope {
    type = "cluster"
  }

  depends_on = [ aws_eks_access_entry.console-allow ]
}

resource "aws_eks_access_entry" "console-allow" {
  cluster_name  = aws_eks_cluster.skills.name
  principal_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
  type          = "STANDARD"
}

resource "aws_eks_access_policy_association" "console-allow" {
  cluster_name  = aws_eks_cluster.skills.name
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  principal_arn = aws_eks_access_entry.console-allow.principal_arn

  access_scope {
    type = "cluster"
  }

  depends_on = [ aws_eks_access_entry.console-allow ]
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

  depends_on = [ aws_eks_node_group.addon,aws_eks_node_group.app ]
}

resource "aws_eks_addon" "vpc-cni" {
  cluster_name = aws_eks_cluster.skills.name
  addon_name   = "vpc-cni"
  addon_version = "v1.16.0-eksbuild.1"
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "eks-pod-identity-agent" {
  cluster_name = aws_eks_cluster.skills.name
  addon_name   = "eks-pod-identity-agent"
  addon_version = "v1.2.0-eksbuild.1"
  resolve_conflicts_on_update = "OVERWRITE"
}

data "tls_certificate" "cluster" {
  url = aws_eks_cluster.skills.identity[0].oidc[0].issuer
  }

# resource "aws_security_group" "control-plane" {
#   name        = "control-plane-sg"
#   description = "Allow HTTPS traffic"
#   vpc_id      = aws_vpc.main.id

#   ingress {
#     from_port        = 443
#     to_port          = 443
#     protocol         = "tcp"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }

#   egress {
#     from_port        = 0
#     to_port          = 0
#     protocol         = "-1"
#     cidr_blocks      = ["0.0.0.0/0"]
#     ipv6_cidr_blocks = ["::/0"]
#   }
#     tags = {
#         Name = "control-plane-sg"
#     }
# }

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