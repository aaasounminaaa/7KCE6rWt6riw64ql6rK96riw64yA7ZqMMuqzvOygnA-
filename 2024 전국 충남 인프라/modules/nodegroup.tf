resource "aws_eks_node_group" "order" {
  cluster_name    = aws_eks_cluster.skills.name
  node_group_name = "wsc2024-db-application-ng"
  node_role_arn   = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.private_a.id, aws_subnet.private_b.id
  ]
  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.medium"]
  # resources = [{
  #   "remote_access_security_group_id"=""
  # }]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 10
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    "app" = "db"
  }

  launch_template {
    name    = aws_launch_template.order.name
    version = aws_launch_template.order.latest_version
  }

  depends_on = [
    aws_eks_access_policy_association.root-allow
  ]
}



resource "aws_iam_role" "nodes" {
  name = "AmazonEKSNodeRole"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}

resource "aws_launch_template" "order" {
  name = "wsc2024-db-application-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "wsc2024-db-application-node"
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
  node_group_name = "wsc2024-other-ng"
  node_role_arn   = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.prod_a.id, aws_subnet.prod_b.id
  ]
  capacity_type  = "ON_DEMAND"
  instance_types = ["t3.medium"]

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 7
  }

  update_config {
    max_unavailable = 1
  }

  labels = {
    "app" = "other"
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
  name = "wsc2024-other-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "wsc2024-other-node"
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