resource "aws_vpc" "main" {
  cidr_block = "10.1.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsi-vpc"
  }
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
 
resource "aws_route" "public" {
  route_table_id = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.main.id
}

## Public Subnet
resource "aws_subnet" "public_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.2.0/24"
  availability_zone = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsi-public-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.3.0/24"
  availability_zone = "ap-northeast-2b"
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

# app

## Elastic IP
resource "aws_eip" "app_a" {
}

resource "aws_eip" "app_b" {
}

## NAT Gateway
resource "aws_nat_gateway" "app_a" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.app_a.id
  subnet_id = aws_subnet.public_a.id

  tags = {
    Name = "wsi-natgw-a"
  }
}

resource "aws_nat_gateway" "app_b" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.app_b.id
  subnet_id = aws_subnet.public_b.id

  tags = {
    Name = "wsi-natgw-b"
  }
}

## Route Table
resource "aws_route_table" "app_a" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-app-a-rt"
  }
}

resource "aws_route_table" "app_b" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-app-b-rt"
  }
}

resource "aws_route" "app_a" {
  route_table_id = aws_route_table.app_a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.app_a.id
}

resource "aws_route" "app_b" {
  route_table_id = aws_route_table.app_b.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.app_b.id
}

resource "aws_subnet" "app_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.0.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsi-app-a"
  }
}

resource "aws_subnet" "app_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.1.0/24"
  availability_zone = "ap-northeast-2b"

  tags = {
    Name = "wsi-app-b"
  }
}

## Attach app Subnet in Route Table
resource "aws_route_table_association" "app_a" {
  subnet_id = aws_subnet.app_a.id
  route_table_id = aws_route_table.app_a.id
}

resource "aws_route_table_association" "app_b" {
  subnet_id = aws_subnet.app_b.id
  route_table_id = aws_route_table.app_b.id
}

# data

#Route Table
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-data-rt"
  }
}

## data Subnet
resource "aws_subnet" "data_a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.4.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsi-data-a"
  }
}

resource "aws_subnet" "data_b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.1.5.0/24"
  availability_zone = "ap-northeast-2b"

  tags = {
    Name = "wsi-data-b"
  }
}

## Attach data Subnet in Route Table
resource "aws_route_table_association" "data_a" {
  subnet_id = aws_subnet.data_a.id
  route_table_id = aws_route_table.data.id
}

resource "aws_route_table_association" "data_b" {
  subnet_id = aws_subnet.data_b.id
  route_table_id = aws_route_table.data.id
}

# EC2
## AMI
data "aws_ssm_parameter" "latest_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-x86_64"
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


## Public EC2
resource "aws_instance" "bastion" {
  ami = data.aws_ssm_parameter.latest_ami.value
  subnet_id = aws_subnet.public_a.id
  instance_type = "t3.small"
  key_name = aws_key_pair.keypair.key_name
  vpc_security_group_ids = [aws_security_group.bastion.id]
  associate_public_ip_address = true
  iam_instance_profile = aws_iam_instance_profile.bastion.name
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y jq curl wget zip
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    ln -s /usr/local/bin/aws /usr/bin/
    ln -s /usr/local/bin/aws_completer /usr/bin/
    sed -i "s|#PasswordAuthentication no|PasswordAuthentication yes|g" /etc/ssh/sshd_config
    echo "Port 4272" >> /etc/ssh/sshd_config
    systemctl restart sshd
    echo 'Skill53!@#' | passwd --stdin ec2-user
    echo 'Skill53!@#' | passwd --stdin root
    curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
    sudo mv /tmp/eksctl /usr/local/bin
    curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.3/2024-04-19/bin/linux/amd64/kubectl
    chmod +x kubectl
    mv kubectl /usr/local/bin
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 get_helm.sh
    ./get_helm.sh
    mv get_helm.sh /usr/local/bin
    yum install -y docker
    systemctl enable --now docker
    usermod -aG docker ec2-user
    usermod -aG docker root
    chmod 666 /var/run/docker.sock
    sudo dnf install -y mariadb105
  EOF
  tags = {
    Name = "wsi-bastion"
  }
}

## Public Security Group
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
    from_port = "80"
    to_port = "80"
  }
 

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "443"
    to_port = "443"
  }

    tags = {
    Name = "wsi-bastion-sg"
  }
}

## IAM
resource "aws_iam_role" "bastion" {
  name = "wsi-bastion-role"
  
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
  name = "wsi-profile-bastion"
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

## app Subnet
output "app_a" {
  value = aws_subnet.app_a.id
}

output "app_b" {
  value = aws_subnet.app_b.id
}

output "data_a" {
    value = aws_subnet.data_a.id
}

output "data_b" {
    value = aws_subnet.data_b.id
}

output "bastion" {
  value = aws_instance.bastion.public_ip
}

output "bastion-sg" {
  value = aws_security_group.bastion.id
}