locals {
  aws_ecr_repository      = "wsi-ecr-repo"
}

resource "aws_vpc" "main" {
  cidr_block = "10.1.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsi-vpc"
  }
}

data "aws_iam_policy_document" "vpc_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "role" {
    name = "wsi-flow-role"
    assume_role_policy = data.aws_iam_policy_document.vpc_assume_role.json
}

data "aws_iam_policy_document" "policy" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "role" {
  name   = "wsi-flow-policy"
  role   = aws_iam_role.role.id
  policy = data.aws_iam_policy_document.policy.json
}

resource "aws_cloudwatch_log_group" "cw_group" {
    name = "/aws/vpc/wsi-vpc"
}

resource "aws_flow_log" "flow_log" {
    iam_role_arn = aws_iam_role.role.arn
    log_destination = aws_cloudwatch_log_group.cw_group.arn
    traffic_type = "ALL"
    vpc_id = aws_vpc.main.id
}

# Public

## Internet Gateway
resource"aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-igw"
  }
}

## Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-public-rt"
  }
}
data "aws_region" "current" {}
resource "aws_route" "public" {
  route_table_id = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.main.id
}

## Public Subnet
resource "aws_subnet" "public_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.2.0/24"
  availability_zone = "${var.create_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsi-public-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.3.0/24"
  availability_zone = "${var.create_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsi-public-b"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "public_a" {
  subnet_id = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

# Private

## Elastic IP
resource "aws_eip" "private_a" {
}

resource "aws_eip" "private_b" {
}

## NAT Gateway
resource "aws_nat_gateway" "private_a" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.private_a.id
  subnet_id = aws_subnet.public_a.id

  tags = {
    Name = "wsi-natgw-a"
  }
}

resource "aws_nat_gateway" "private_b" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.private_b.id
  subnet_id = aws_subnet.public_b.id

  tags = {
    Name = "wsi-natgw-b"
  }
}

## Route Table
resource "aws_route_table" "private_a" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-app-a-rt"
  }
}

resource "aws_route_table" "private_b" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-app-b-rt"
  }
}

resource "aws_route" "private_a" {
  route_table_id = aws_route_table.private_a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.private_a.id
}

resource "aws_route" "private_b" {
  route_table_id = aws_route_table.private_b.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.private_b.id
}

resource "aws_subnet" "private_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.0.0/24"
  availability_zone = "${var.create_region}a"

  tags = {
    Name = "wsi-app-a"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.1.0/24"
  availability_zone = "${var.create_region}b"

  tags = {
    Name = "wsi-app-b"
  }
}

## Attach Private Subnet in Route Table
resource "aws_route_table_association" "private_a" {
  subnet_id = aws_subnet.private_a.id
  route_table_id = aws_route_table.private_a.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id = aws_subnet.private_b.id
  route_table_id = aws_route_table.private_b.id
}

resource "aws_subnet" "protect_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.4.0/24"
  availability_zone = "${var.create_region}a"

  tags = {
    Name = "wsi-data-a"
  }
}

resource "aws_subnet" "protect_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.5.0/24"
  availability_zone = "${var.create_region}b"

  tags = {
    Name = "wsi-data-b"
  }
}
resource "aws_route_table_association" "protect_a" {
  subnet_id = aws_subnet.protect_a.id
  route_table_id = aws_route_table.protect_a.id
}

resource "aws_route_table_association" "protect_b" {
  subnet_id = aws_subnet.protect_a.id
  route_table_id = aws_route_table.protect_a.id
}

resource "aws_route_table" "protect_a" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-data-rt"
  }
}

# EC2
## AMI
data "aws_ami" "amazonlinux2023" {
  most_recent = true

  filter {
    name   = "name"
    values = ["al2023-ami-*x86*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["137112412989"] # Amazon's official account ID
}

## Keypair
resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits = 4096
}

resource "aws_key_pair" "keypair" {
  key_name = "wsi"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "keypair" {
  content = tls_private_key.rsa.private_key_pem
  filename = "./wsi.pem"
}

resource "random_string" "seoul_random" {
  length           = 3
  upper   = false
  lower   = false
  numeric  = true
  special = false
}

resource "aws_s3_bucket" "seoul-object" {
  bucket = "seoul-object-${random_string.seoul_random.result}"
  force_destroy = true
}

resource "aws_s3_object" "seoul-customer" {
  bucket = aws_s3_bucket.seoul-object.id
  key    = "/customer-app/customer"
  source = "./app/customer-app/customer"
  etag   = filemd5("./app/customer-app/customer")
}

resource "aws_s3_object" "seoul-customer-Dockerfile" {
  bucket = aws_s3_bucket.seoul-object.id
  key    = "/customer-app/Dockerfile"
  source = "./app/customer-app/Dockerfile"
  etag   = filemd5("./app/customer-app/Dockerfile")
}

resource "aws_s3_object" "seoul-order" {
  bucket = aws_s3_bucket.seoul-object.id
  key    = "/order-app/order"
  source = "./app/order-app/order"
  etag   = filemd5("./app/order-app/order")
}

resource "aws_s3_object" "seoul-order-Dockerfile" {
  bucket = aws_s3_bucket.seoul-object.id
  key    = "/order-app/Dockerfile"
  source = "./app/order-app/Dockerfile"
  etag   = filemd5("./app/order-app/Dockerfile")
}

resource "aws_s3_object" "seoul-product" {
  bucket = aws_s3_bucket.seoul-object.id
  key    = "/product-app/product"
  source = "./app/product-app/product"
  etag   = filemd5("./app/product-app/product")
}

resource "aws_s3_object" "seoul-product-Dockerfile" {
  bucket = aws_s3_bucket.seoul-object.id
  key    = "/product-app/Dockerfile"
  source = "./app/product-app/Dockerfile"
  etag   = filemd5("./app/product-app/Dockerfile")
}

data "aws_region" "seoul" {}
data "aws_caller_identity" "seoul" {}

## Public EC2
resource "aws_instance" "bastion" {
  ami = data.aws_ami.amazonlinux2023.id
  subnet_id = aws_subnet.public_a.id
  instance_type = "t3.small"
  key_name = aws_key_pair.keypair.key_name
  vpc_security_group_ids = [aws_security_group.bastion.id]
  associate_public_ip_address = true
  iam_instance_profile = aws_iam_instance_profile.bastion.name
  user_data = <<-EOF
  #!/bin/bash
  echo "skills2024" | passwd --stdin ec2-user
  sed -i 's|.*PasswordAuthentication.*|PasswordAuthentication yes|g' /etc/ssh/sshd_config
  echo "Port 4272" >> /etc/ssh/sshd_config
  systemctl restart sshd
  yum update -y
  yum install -y curl jq
  yum install -y docker
  systemctl enable --now docker
  usermod -aG docker ec2-user
  usermod -aG docker root
  chmod 666 /var/run/docker.sock
  curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
  mv /tmp/eksctl /usr/bin
  curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.0/2024-01-04/bin/linux/amd64/kubectl
  chmod +x ./kubectl
  mv -f ./kubectl /usr/local/bin/kubectl
  curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  sudo chmod 700 get_helm.sh
  ./get_helm.sh
  sudo mv ./get_helm.sh /usr/local/bin
  sudo dnf install -y mariadb105
  HOME=/home/ec2-user
  echo "export AWS_DEFAULT_REGION=${data.aws_region.seoul.name}" >> ~/.bashrc
  echo "export AWS_ACCOUNT_ID=${data.aws_caller_identity.seoul.account_id}" >> ~/.bashrc
  source ~/.bashrc
  su - ec2-user -c 'aws s3 cp s3://${aws_s3_bucket.seoul-object.id}/ ~/ --recursive'
  aws ecr get-login-password --region ${data.aws_region.seoul.name} | docker login --username AWS --password-stdin ${data.aws_caller_identity.seoul.account_id}.dkr.ecr.${data.aws_region.seoul.name}.amazonaws.com
  docker build -t ${aws_ecr_repository.customer.repository_url}:latest ~/customer-app/
  docker build -t ${aws_ecr_repository.order.repository_url}:latest ~/order-app/
  docker build -t ${aws_ecr_repository.product.repository_url}:latest ~/product-app/
  docker push ${aws_ecr_repository.customer.repository_url}:latest
  docker push ${aws_ecr_repository.order.repository_url}:latest
  docker push ${aws_ecr_repository.product.repository_url}:latest
  aws s3 rm s3://${aws_s3_bucket.seoul-object.id} --recursive
  aws s3 rb s3://${aws_s3_bucket.seoul-object.id} --force
  EOF
  tags = {
    Name = "wsi-bastion"
  }
}

## Public Security Group

resource "aws_security_group" "control" {
  name = "control-plan-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }

  egress {
    protocol = -1
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 0
  }
    tags = {
    Name = "control-plan-sg"
  }
}

resource "aws_security_group" "bastion" {
  name = "wsi-bastion-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "4272"
    to_port = "4272"
  }

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "80"
    to_port = "80"
  }

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "3307"
    to_port = "3307"
  }

    tags = {
    Name = "wsi-bastion-sg"
  }
}

data "aws_ec2_managed_prefix_list" "cloudfront" {
 name = "com.amazonaws.global.cloudfront.origin-facing"
}

## ALB Security Group
resource "aws_security_group" "alb-bastion" {
  name = "wsi-app-alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
    from_port = "80"
    to_port = "80"
  }
  egress {
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "0"
    to_port = "0"
  }
    tags = {
    Name = "wsi-app-alb-sg"
  }
}


resource "random_string" "random" {
  length           = 5
  upper   = false
  lower   = false
  numeric  = true
  special = false
}

## IAM
resource "aws_iam_role" "bastion" {
  name = "wsi-role-bastion"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_iam_instance_profile" "bastion" {
  name = "wsi-bastion-role"
  role = aws_iam_role.bastion.name
}

resource "aws_security_group" "endpoint" {
  name = "wsi-endpoint-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }
  egress {
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "0"
    to_port = "0"
  }
    tags = {
    Name = "wsi-endpoint-sg"
  }
}

### endpoint
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.ap-northeast-2.dynamodb"
  vpc_endpoint_type = "Interface"

  security_group_ids = [
    aws_security_group.endpoint.id
  ]
  tags = {
    Name = "wsi-dynamodb-endpoint"
  }
}

resource "aws_vpc_endpoint_subnet_association" "main_a" {
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb.id
  subnet_id       = aws_subnet.private_a.id
}
resource "aws_vpc_endpoint_subnet_association" "main_b" {
  vpc_endpoint_id = aws_vpc_endpoint.dynamodb.id
  subnet_id       = aws_subnet.private_b.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.ap-northeast-2.s3"
  vpc_endpoint_type = "Gateway"
  tags = {
    Name = "wsi-s3-endpoint"
  }
  depends_on = [aws_vpc_endpoint.dynamodb,aws_vpc_endpoint_subnet_association.main_a,aws_vpc_endpoint_subnet_association.main_b ]
}

resource "aws_vpc_endpoint_route_table_association" "private_a" {
  route_table_id  = aws_route_table.private_a.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}

resource "aws_vpc_endpoint_route_table_association" "private_b" {
  route_table_id  = aws_route_table.private_b.id
  vpc_endpoint_id = aws_vpc_endpoint.s3.id
}


# OutPut

## VPC
output "aws_vpc" {
  value = aws_vpc.main.id
}

## Public Subnet
output "public_a" {
  value = aws_subnet.public_a.id
}

output "public_b" {
  value = aws_subnet.public_b.id
}

## Private Subnet
output "private_a" {
  value = aws_subnet.private_a.id
}

output "private_b" {
  value = aws_subnet.private_b.id
}

output "protect_a" {
  value = aws_subnet.protect_a.id
}

output "protect_b" {
  value = aws_subnet.protect_b.id
}

output "bastion" {
  value = aws_instance.bastion.id
}

output "bastion-sg" {
  value = aws_security_group.bastion.id
}