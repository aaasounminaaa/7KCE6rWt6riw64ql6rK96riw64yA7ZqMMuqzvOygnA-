# locals {
#     eks_version = "1.29"
#     path = "./config"
# }

# data "aws_ssm_parameter" "bottlerocket_image_id" {
#   name = "/aws/service/bottlerocket/aws-k8s-${local.eks_version}/x86_64/latest/image_id"
# }

# data "aws_ssm_parameter" "bottlerocket_image_id_arn" {
#   name = "/aws/service/bottlerocket/aws-k8s-${local.eks_version}/arm64/latest/image_id"
# }

# data "aws_ami" "bottlerocket_image" {
#   owners = ["amazon"]
#   filter {
#     name   = "image-id"
#     values = [data.aws_ssm_parameter.bottlerocket_image_id.value]
#   }
# }

# data "aws_ami" "bottlerocket_image-arn" {
#   owners = ["amazon"]
#   filter {
#     name   = "image-id"
#     values = [data.aws_ssm_parameter.bottlerocket_image_id_arn.value]
#   }
# }
# resource "aws_eks_node_group" "addon" {
#   cluster_name    = aws_eks_cluster.skills.name
#   node_group_name = "wsi-addon-nodegroup"
#   node_role_arn   = aws_iam_role.nodes.arn

#   subnet_ids = [
#     aws_subnet.private_a.id, aws_subnet.private_b.id
#   ]
#   instance_types = ["t4g.large"]

#   scaling_config {
#     desired_size = 2
#     min_size     = 2
#     max_size     = 10
#   }

#   update_config {
#     max_unavailable = 1
#   }

#   labels = {
#     "wsi" = "addon"
#   }
#   lifecycle {
#     create_before_destroy = true
#   }
#   launch_template {
#     name    = aws_launch_template.addon_bottlerocket_lt.name
#     version = aws_launch_template.addon_bottlerocket_lt.latest_version
#   }

#   depends_on = [
#     aws_eks_access_policy_association.console-allow
#   ]
# }



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



# resource "aws_launch_template" "addon_bottlerocket_lt" {
#   image_id               = data.aws_ami.bottlerocket_image-arn.id
#   name = "wsi-addon-node-lt"
#   update_default_version = true

#   block_device_mappings {
#     device_name = "/dev/xvda"

#     ebs {
#       volume_size           = 30
#       volume_type           = "gp2"
#       delete_on_termination = true
#     }
#   }
#   tag_specifications {
#     resource_type = "instance"

#     tags = {
#       "Name"                                                          = "wsi-addon-node"
#       "kubernetes.io/cluster/${aws_eks_cluster.skills.name}"     = "owned"
#       "k8s.io/cluster-autoscaler/${aws_eks_cluster.skills.name}" = "owned"
#       "k8s.io/cluster-autoscaler/enabled"                             = "true"
#     }
#   }

#   network_interfaces {
#     associate_public_ip_address = false
#   }
#   metadata_options {
#     http_tokens                 = "required"
#     http_put_response_hop_limit = 2
#   }
#   # BottleRocket Configuration File. See Below This Code Block.
#   user_data = base64encode(templatefile("${local.path}/config.toml",
#     {
#       "cluster_name"             = aws_eks_cluster.skills.name
#       "endpoint"                 = aws_eks_cluster.skills.endpoint
#       "cluster_auth_base64"      = aws_eks_cluster.skills.certificate_authority[0].data
#       "aws_region"               = "ap-northeast-2"
#       "enable_admin_container"   = false
#       "enable_control_container" = true
#     }
#   ))
#   depends_on = [
#     aws_eks_cluster.skills
#   ]
# }


# resource "aws_eks_node_group" "app" {
#   cluster_name    = aws_eks_cluster.skills.name
#   node_group_name = "wsi-app-nodegroup"
#   node_role_arn   = aws_iam_role.nodes.arn

#   subnet_ids = [
#     aws_subnet.private_a.id, aws_subnet.private_a.id
#   ]
# #   ami_type       = "BOTTLEROCKET_x86_64"
# #   capacity_type  = "ON_DEMAND"
#   instance_types = ["m5.xlarge"]

#   scaling_config {
#     desired_size = 2
#     min_size     = 2
#     max_size     = 7
#   }

#   update_config {
#     max_unavailable = 1
#   }

#   labels = {
#     "wsi" = "product"
#     "app" = "customer"
#   }

#   launch_template {
#     name    = aws_launch_template.app.name
#     version = aws_launch_template.app.latest_version
#   }

#   depends_on = [
#     aws_eks_access_policy_association.console-allow
#   ]
# }

# resource "aws_launch_template" "app" {
#   name = "wsi-app-node-lt"
#   image_id               = data.aws_ami.bottlerocket_image.id
#   update_default_version = true
#   block_device_mappings {
#     device_name = "/dev/xvda"

#     ebs {
#       volume_size           = 30
#       volume_type           = "gp2"
#       delete_on_termination = true
#     }
#   }
#   tag_specifications {
#     resource_type = "instance"
#     tags = {
#       "Name"                                                          = "wsi-app-node"
#       "kubernetes.io/cluster/${aws_eks_cluster.skills.name}"     = "owned"
#       "k8s.io/cluster-autoscaler/${aws_eks_cluster.skills.name}" = "owned"
#       "k8s.io/cluster-autoscaler/enabled"                             = "true"
#     }
#   }
#   network_interfaces {
#     associate_public_ip_address = false
#   }

#   metadata_options {
#     http_tokens                 = "required"
#     http_put_response_hop_limit = 1
#   }
#   # BottleRocket Configuration File. See Below This Code Block.
#   user_data = base64encode(templatefile("${local.path}/config.toml",
#     {
#       "cluster_name"             = aws_eks_cluster.skills.name
#       "endpoint"                 = aws_eks_cluster.skills.endpoint
#       "cluster_auth_base64"      = aws_eks_cluster.skills.certificate_authority[0].data
#       "aws_region"               = "ap-northeast-2"
#       "enable_admin_container"   = false
#       "enable_control_container" = true
#     }
#   ))
# }


# resource "aws_eks_fargate_profile" "example" {
#   cluster_name           = aws_eks_cluster.skills.name
#   fargate_profile_name   = "wsi-app-fargate"
#   pod_execution_role_arn = aws_iam_role.example.arn
#   subnet_ids             = [aws_subnet.private_a.id, aws_subnet.private_b.id]

#   selector {
#     namespace = "wsi"
#     labels = {
#       "wsi" = "order"
#     }
#   }
# }


# resource "aws_iam_role" "example" {
#   name = "eks-wsi-profile-example"

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