resource "aws_eks_node_group" "app" {
  cluster_name    = aws_eks_cluster.skills.name
  node_group_name = "wsi-app-ng"
  node_role_arn   = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.private_a.id, aws_subnet.private_b.id,aws_subnet.private_c.id
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
    "wsi/node" = "app"
  }

  launch_template {
    name    = aws_launch_template.app.name
    version = aws_launch_template.app.latest_version
  }

  depends_on = [
    aws_eks_access_policy_association.console-allow
  ]
  lifecycle {
    create_before_destroy = true
  }
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

resource "aws_launch_template" "app" {
  name = "wsi-app-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "wsi-app-instance"
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

resource "aws_eks_node_group" "addon" {
  cluster_name    = aws_eks_cluster.skills.name
  node_group_name = "wsi-addon-ng"
  node_role_arn   = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.private_a.id, aws_subnet.private_b.id,aws_subnet.private_c.id
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
    "wsi/node" = "addon"
  }

  launch_template {
    name    = aws_launch_template.addon.name
    version = aws_launch_template.addon.latest_version
  }

  depends_on = [
    aws_eks_access_policy_association.console-allow
  ]
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_launch_template" "addon" {
  name = "wsi-addon-lt"

  tag_specifications {
    resource_type = "instance"

    tags = {
      Name = "wsi-addon-instance"
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