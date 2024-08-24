locals {
  aws_ecr_repository      = "hrdkorea-ecr-repo"
}

resource "aws_vpc" "main" {
  cidr_block = "10.129.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "hrdkorea-vpc"
  }
}

# Public

## Internet Gateway
resource"aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "hrdkorea-IGW"
  }
}

## Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "hrdkorea-public-rt"
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
  cidr_block = "10.129.0.0/24"
  availability_zone = "${var.create_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "hrdkorea-public-sn-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.129.1.0/24"
  availability_zone = "${var.create_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "hrdkorea-public-sn-b"
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
    Name = "hrdkorea-NGW-a"
  }
}

resource "aws_nat_gateway" "private_b" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.private_b.id
  subnet_id = aws_subnet.public_b.id

  tags = {
    Name = "hrdkorea-NGW-b"
  }
}

## Route Table
resource "aws_route_table" "private_a" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "hrdkorea-private-a-rt"
  }
}

resource "aws_route_table" "private_b" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "hrdkorea-private-b-rt"
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
  cidr_block = "10.129.11.0/24"
  availability_zone = "${var.create_region}a"

  tags = {
    Name = "hrdkorea-private-sn-a"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.129.12.0/24"
  availability_zone = "${var.create_region}b"

  tags = {
    Name = "hrdkorea-private-sn-b"
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
  cidr_block = "10.129.21.0/24"
  availability_zone = "${var.create_region}a"

  tags = {
    Name = "hrdkorea-protect-sn-a"
  }
}

resource "aws_subnet" "protect_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.129.22.0/24"
  availability_zone = "${var.create_region}b"

  tags = {
    Name = "hrdkorea-protect-sn-b"
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
    Name = "hrdkorea-protect-rt"
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

resource "random_string" "file_random" {
  length           = 3
  upper            = false
  lower            = false
  numeric          = true
  special          = false
}

resource "aws_s3_bucket" "app" {
  bucket = "app-${random_string.file_random.result}"
  force_destroy = true
}

resource "aws_s3_object" "customer" {
  bucket = aws_s3_bucket.app.id
  key    = "/customer/customer"
  source = "./content/app/customer/customer"
  etag   = filemd5("./content/app/customer/customer")
}

resource "aws_s3_object" "customer-Dockerfile" {
  bucket = aws_s3_bucket.app.id
  key    = "/customer/Dockerfile"
  source = "./content/app/customer/Dockerfile"
  etag   = filemd5("./content/app/customer/Dockerfile")
}

resource "aws_s3_object" "product" {
  bucket = aws_s3_bucket.app.id
  key    = "/product"
  source = "./content/app/product/product"
  etag   = filemd5("./content/app/product/product")
}

resource "aws_s3_object" "customer-Dockerfile" {
  bucket = aws_s3_bucket.app.id
  key    = "/product/Dockerfile"
  source = "./content/app/product/Dockerfile"
  etag   = filemd5("./content/app/product/Dockerfile")
}

resource "aws_s3_object" "order" {
  bucket = aws_s3_bucket.app.id
  key    = "/order"
  source = "./content/app/order/order"
  etag   = filemd5("./content/app/order/order")
}

resource "aws_s3_object" "order-Dockerfile" {
  bucket = aws_s3_bucket.app.id
  key    = "/order/Dockerfile"
  source = "./content/app/order/Dockerfile"
  etag   = filemd5("./content/app/order/Dockerfile")
}

## Public EC2
resource "aws_instance" "bastion" {
  ami = data.aws_ami.amazonlinux2023.id
  subnet_id = aws_subnet.public_a.id
  instance_type = "t3.small"
  key_name = "${var.key_name}"
  vpc_security_group_ids = [aws_security_group.bastion.id]
  associate_public_ip_address = true
  iam_instance_profile = aws_iam_instance_profile.bastion.name
  user_data = <<-EOF
  #!/bin/bash
  echo "skills2024" | passwd --stdin ec2-user
  sed -i 's|.*PasswordAuthentication.*|PasswordAuthentication yes|g' /etc/ssh/sshd_config
  echo "Port 2024" >> /etc/ssh/sshd_config
  systemctl restart sshd
  yum update -y
  yum install -y curl jq
  sudo dnf install -y mariadb105
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
  curl --silent --location "https://github.com/weaveworks/eksctl/releases/lahrdkorea/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
  mv /tmp/eksctl /usr/bin
  curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  sudo chmod 700 get_helm.sh
  ./get_helm.sh
  sudo mv ./get_helm.sh /usr/local/bin
  HOME=/home/ec2-user
  echo "export CLUSTER_NAME=hrdkorea-cluster" >> ~/.bashrc
  echo "export AWS_DEFAULT_REGION=${var.create_region}" >> ~/.bashrc
  echo "export AWS_ACCOUNT_ID=${data.aws_caller_identity.current.account_id}" >> ~/.bashrc
  source ~/.bashrc
  mkdir -p ~/app
  chown ec2-user:ec2-user ~/app
  su - ec2-user -c 'aws s3 cp s3://${aws_s3_bucket.app.id}/ ~/app --recursive'
  aws ecr get-login-password --region ${var.create_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.create_region}.amazonaws.com
  docker build -t ${local.aws_ecr_repository}:order ~/app/order/
  docker build -t ${local.aws_ecr_repository}:product ~/app/product/
  docker build -t ${local.aws_ecr_repository}:customer ./app/customer/
  docker push ${local.aws_ecr_repository}:order
  docker push ${local.aws_ecr_repository}:product
  docker push ${local.aws_ecr_repository}:customer
  aws s3 rm s3://${aws_s3_bucket.app.id} --recursive
  aws s3 rb s3://${aws_s3_bucket.app.id} --force
  EOF
  tags = {
    Name = "hrdkorea-bastion"
  }
}

## Public Security Group
resource "aws_security_group" "bastion" {
  name = "hrdkorea-EC2-SG"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "2024"
    to_port = "2024"
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
    from_port = "3409"
    to_port = "3409"
  }

    tags = {
    Name = "hrdkorea-EC2-SG"
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
  name = "hrdkorea-role-bastion${random_string.random.result}"
  
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
  name = "hrdkorea-profile-bastion${random_string.random.result}"
  role = aws_iam_role.bastion.name
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