resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsi-vpc"
  }
}

# Public

## Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-IGW"
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
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

## Public Subnet
resource "aws_subnet" "public_a" {
  vpc_id                = aws_vpc.main.id
  cidr_block            = "10.0.11.0/24"
  availability_zone     = "ap-northeast-2a"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsi-public-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id                = aws_vpc.main.id
  cidr_block            = "10.0.12.0/24"
  availability_zone     = "ap-northeast-2b"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsi-public-b"
  }
}

resource "aws_subnet" "public_c" {
  vpc_id                = aws_vpc.main.id
  cidr_block            = "10.0.13.0/24"
  availability_zone     = "ap-northeast-2c"
  map_public_ip_on_launch = true

  tags = {
    Name = "wsi-public-c"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_c" {
  subnet_id      = aws_subnet.public_c.id
  route_table_id = aws_route_table.public.id
}

# Private

## Elastic IP
resource "aws_eip" "private_a" {}

resource "aws_eip" "private_b" {}

resource "aws_eip" "private_c" {}

## NAT Gateway
resource "aws_nat_gateway" "private_a" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.private_a.id
  subnet_id     = aws_subnet.public_a.id

  tags = {
    Name = "wsi-NGW-a"
  }
}

resource "aws_nat_gateway" "private_b" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.private_b.id
  subnet_id     = aws_subnet.public_b.id

  tags = {
    Name = "wsi-NGW-b"
  }
}

resource "aws_nat_gateway" "private_c" {
  depends_on = [aws_internet_gateway.main]

  allocation_id = aws_eip.private_c.id
  subnet_id     = aws_subnet.public_c.id

  tags = {
    Name = "wsi-NGW-c"
  }
}

## Route Table
resource "aws_route_table" "private_a" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-private-a-rt"
  }
}

resource "aws_route_table" "private_b" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-private-b-rt"
  }
}

resource "aws_route_table" "private_c" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-private-c-rt"
  }
}

resource "aws_route" "private_a" {
  route_table_id         = aws_route_table.private_a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.private_a.id
}

resource "aws_route" "private_b" {
  route_table_id         = aws_route_table.private_b.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.private_b.id
}

resource "aws_route" "private_c" {
  route_table_id         = aws_route_table.private_c.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.private_c.id
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.101.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsi-private-a"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.102.0/24"
  availability_zone = "ap-northeast-2b"

  tags = {
    Name = "wsi-private-b"
  }
}

resource "aws_subnet" "private_c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.103.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "wsi-private-c"
  }
}

# data

# Route Table
resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wsi-data-rt"
  }
}

## data Subnet
resource "aws_subnet" "data_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.201.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "wsi-data-a"
  }
}

resource "aws_subnet" "data_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.202.0/24"
  availability_zone = "ap-northeast-2b"

  tags = {
    Name = "wsi-data-b"
  }
}

resource "aws_subnet" "data_c" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.203.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "wsi-data-c"
  }
}

## Attach data Subnet in Route Table
resource "aws_route_table_association" "data_a" {
  subnet_id      = aws_subnet.data_a.id
  route_table_id = aws_route_table.data.id
}

resource "aws_route_table_association" "data_b" {
  subnet_id      = aws_subnet.data_b.id
  route_table_id = aws_route_table.data.id
}

resource "aws_route_table_association" "data_c" {
  subnet_id      = aws_subnet.data_c.id
  route_table_id = aws_route_table.data.id
}

## Attach Private Subnet in Route Table
resource "aws_route_table_association" "private_a" {
  subnet_id      = aws_subnet.private_a.id
  route_table_id = aws_route_table.private_a.id
}

resource "aws_route_table_association" "private_b" {
  subnet_id      = aws_subnet.private_b.id
  route_table_id = aws_route_table.private_b.id
}

resource "aws_route_table_association" "private_c" {
  subnet_id      = aws_subnet.private_c.id
  route_table_id = aws_route_table.private_c.id
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
  rsa_bits  = 4096
}

resource "aws_key_pair" "keypair" {
  key_name   = "wsi"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "keypair" {
  content  = tls_private_key.rsa.private_key_pem
  filename = "./wsi.pem"
}

## Public EC2
resource "aws_instance" "bastion" {
  ami                         = data.aws_ami.amazonlinux2023.id
  subnet_id                   = aws_subnet.public_c.id
  instance_type               = "m5.large"
  key_name                    = aws_key_pair.keypair.key_name
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.bastion.name
  user_data = "${file("./src/userdata.sh")}"

  tags = {
    Name = "wsi-bastion-ec2"
    ec2  = "bastion"
  }
}

resource "aws_instance" "control_plane" {
  ami                         = data.aws_ami.amazonlinux2023.id
  subnet_id                   = aws_subnet.private_a.id
  instance_type               = "c5.large"
  key_name                    = aws_key_pair.keypair.key_name
  vpc_security_group_ids      = [aws_security_group.control_plane.id]
  associate_public_ip_address = false 
  iam_instance_profile        = aws_iam_instance_profile.control_plane.name
  user_data                   = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y jq curl wget git
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    sudo ./aws/install
    ln -s /usr/local/bin/aws /usr/bin/
    ln -s /usr/local/bin/aws_completer /usr/bin/
    sed -i "s|PasswordAuthentication no|PasswordAuthentication yes|g" /etc/ssh/sshd_config
    echo "Port 3817" >> /etc/ssh/sshd_config
    systemctl restart sshd
    echo 'Skills2024**' | passwd --stdin ec2-user
    echo 'Skills2024**' | passwd --stdin root
    curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
    mv /tmp/eksctl /usr/local/bin
    curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.3/2024-04-19/bin/linux/amd64/kubectl
    chmod +x kubectl
    mv kubectl /usr/local/bin
    curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 get_helm.sh
    ./get_helm.sh
    mv ./get_helm.sh /usr/local/bin
    dnf install -y mariadb105
    yum install -y docker
    systemctl enable --now docker
    usermod -aG docker ec2-user
    usermod -aG docker root
    chmod 666 /var/run/docker.sock
    useradd user
    useradd dev
    echo 'Skills2024**' | passwd --stdin user
    echo 'Skills2024**' | passwd --stdin dev
  EOF
  tags = {
    Name = "wsi-control-plane"
  }
}

## Public Security Group
resource "aws_security_group" "bastion" {
  name   = "wsi-bastion-SG"
  description = "wsi-bastion-SG"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 2222
    to_port     = 2222
  }

  egress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 80
    to_port     = 80
  }

  egress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
  }

  egress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 3817
    to_port     = 3817
  }

  tags = {
    Name = "wsi-bastion-SG"
  }
}

resource "aws_security_group" "control_plane" {
  name   = "wsi-control-plane-SG"
  description = "wsi-control-plane-SG"
  vpc_id = aws_vpc.main.id

  ingress {
    protocol    = "tcp"
    security_groups = [aws_security_group.bastion.id]
    from_port   = 3817
    to_port     = 3817
  }

  egress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 80
    to_port     = 80
  }

  egress {
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
  }

  tags = {
    Name = "wsi-bastion-SG"
  }
}

resource "aws_eip" "bastion" {
  instance = aws_instance.bastion.id
  associate_with_private_ip = aws_instance.bastion.private_ip
}

## IAM
resource "aws_iam_role" "bastion" {
  name = "wsi-bastion-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Sid       = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/PowerUserAccess"]

  tags = {
    Name = "wsi-bastion-role"
  }
}

resource "aws_iam_role_policy_attachment" "policy" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
}

resource "aws_iam_role" "control_plane" {
  name = "wsi-control-plane-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Effect    = "Allow"
        Sid       = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]

  tags = {
    Name = "wsi-bastion-role"
  }
}

resource "aws_iam_instance_profile" "bastion" {
  name = "wsi-bastion-role"
  role = aws_iam_role.bastion.name
}


resource "aws_iam_instance_profile" "control_plane" {
  name = "wsi-control-plane-role"
  role = aws_iam_role.control_plane.name
}

# Output

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

output "public_c" {
  value = aws_subnet.public_c.id
}

## Private Subnet
output "private_a" {
  value = aws_subnet.private_a.id
}

output "private_b" {
  value = aws_subnet.private_b.id
}

output "private_c" {
  value = aws_subnet.private_c.id
}

output "data_a" {
  value = aws_subnet.data_a.id
}

output "data_b" {
  value = aws_subnet.data_b.id
}

output "data_c" {
  value = aws_subnet.data_c.id
}

output "bastion" {
  value = aws_instance.bastion.id
}

output "bastion-sg" {
  value = aws_security_group.bastion.id
}
