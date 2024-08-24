resource "aws_eks_node_group" "order" {
  cluster_name    = aws_eks_cluster.skills.name
  node_group_name = "hrdkorea-order-ng"
  node_role_arn   = "${var.node_role}"

  subnet_ids = [
    aws_subnet.private_a.id, aws_subnet.private_b.id
  ]

  ami_type       = "BOTTLEROCKET_x86_64"
  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.large"]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 10
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    "skills/dedicated" = "order"
  }

  launch_template {
    name    = aws_launch_template.order.name
    version = aws_launch_template.order.latest_version
  }

  depends_on = [
    aws_eks_access_policy_association.root-allow
  ]
}



# resource "aws_iam_role" "nodes" {
#   name = "AmazonEKSNodeRole"

#   assume_role_policy = jsonencode({
#     Statement = [{
#       Action = "sts:AssumeRole"
#       Effect = "Allow"
#       Principal = {
#         Service = "ec2.amazonaws.com"
#       }
#     }]
#     Version = "2012-10-17"
#   })
# }

# resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
#   role       = aws_iam_role.nodes.name
# }

# resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
#   role       = aws_iam_role.nodes.name
# }

# resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
#   role       = aws_iam_role.nodes.name
# }

resource "aws_launch_template" "order" {
  name = "hrdkorea-order-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "hrdkorea-order-ng"
    }
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
}

resource "aws_eks_node_group" "customer" {
  cluster_name    = aws_eks_cluster.skills.name
  node_group_name = "hrdkorea-customer-ng"
  node_role_arn   = "${var.node_role}"

  subnet_ids = [
    aws_subnet.private_a.id, aws_subnet.private_b.id
  ]

  ami_type       = "BOTTLEROCKET_x86_64"
  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.large"]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 7
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    "skills/dedicated" = "customer"
  }

  launch_template {
    name    = aws_launch_template.customer.name
    version = aws_launch_template.customer.latest_version
  }

  depends_on = [
    aws_eks_access_policy_association.root-allow
  ]
}

resource "aws_launch_template" "customer" {
  name = "hrdkorea-customer-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "hrdkorea-customer-ng"
    }
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
}

resource "aws_eks_node_group" "product" {
  cluster_name    = aws_eks_cluster.skills.name
  node_group_name = "hrdkorea-product-ng"
  node_role_arn   = "${var.node_role}"

  subnet_ids = [
    aws_subnet.private_a.id, aws_subnet.private_b.id
  ]

  ami_type       = "BOTTLEROCKET_x86_64"
  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.large"]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 7
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    "skills/dedicated" = "product"
  }

  launch_template {
    name    = aws_launch_template.product.name
    version = aws_launch_template.product.latest_version
  }

  depends_on = [
    aws_eks_access_policy_association.root-allow
  ]
}

resource "aws_launch_template" "product" {
  name = "hrdkorea-product-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "hrdkorea-product-ng"
    }
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = 30
      volume_type           = "gp2"
      delete_on_termination = true
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
}

resource "aws_eks_fargate_profile" "example" {
  cluster_name           = aws_eks_cluster.skills.name
  fargate_profile_name   = "hrdkorea-addon-profile"
  pod_execution_role_arn = "${var.fargate_role}"
  subnet_ids             = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  selector {
    namespace = "kube-system"
    # labels = {
    #   "hrdkorea" = "addon"
    # }
  }

  selector {
    namespace = "hrdkorea"
    labels = {
      "hrdkorea" = "addon"
    }
  }

}


# resource "aws_iam_role" "example" {
#   name = "eks-fargate-profile-example"

#   assume_role_policy = jsonencode({
#     Statement = [{
#       Action = "sts:AssumeRole"
#       Effect = "Allow"
#       Principal = {
#         Service = "eks-fargate-pods.amazonaws.com"
#       }
#     }]
#     Version = "2012-10-17"
#   })
# }

# resource "aws_iam_role_policy_attachment" "example-AmazonEKSFargatePodExecutionRolePolicy" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
#   role       = aws_iam_role.example.name
# }