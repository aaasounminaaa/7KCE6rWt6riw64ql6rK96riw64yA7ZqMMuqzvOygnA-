resource "aws_vpc" "ma" {
  cidr_block = "10.0.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support = true

  tags = {
    Name = "wsc2024-ma-vpc"
  }
}

# Public
## Internet Gateway
resource"aws_internet_gateway" "ma" {
  vpc_id = aws_vpc.ma.id

  tags = {
    Name = "wsc2024-ma-mgmt-igw"
  }
}

## Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ma.id

  tags = {
    Name = "wsc2024-ma-mgmt-rt"
  }
}

resource "aws_route" "public" {
  route_table_id = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.ma.id
}

resource "aws_route" "public_tgw_prod" {
  route_table_id = aws_route_table.public.id
  destination_cidr_block = "172.16.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

resource "aws_route" "public_tgw_storage" {
  route_table_id = aws_route_table.public.id
  destination_cidr_block = "192.168.0.0/16"
  gateway_id = aws_ec2_transit_gateway.example.id
  depends_on = [ aws_ec2_transit_gateway.example,aws_ec2_transit_gateway_vpc_attachment.ma ]
}

## Public Subnet
resource "aws_subnet" "public_a" {
  vpc_id = aws_vpc.ma.id
  cidr_block = "10.0.0.0/24"
  availability_zone = "${var.create_region}a"
  # map_public_ip_on_launch = true

  tags = {
    Name = "wsc2024-ma-mgmt-sn-a"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "public_a" {
  subnet_id = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

## Public Subnet
resource "aws_subnet" "public_b" {
  vpc_id = aws_vpc.ma.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "${var.create_region}a"
  # map_public_ip_on_launch = true

  tags = {
    Name = "wsc2024-ma-mgmt-sn-b"
  }
}

## Attach Public Subnet in Route Table
resource "aws_route_table_association" "public_b" {
  subnet_id = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_flow_log" "flow_log" {
    iam_role_arn = aws_iam_role.role.arn
    log_destination = aws_cloudwatch_log_group.cw_group.arn
    traffic_type = "ALL"
    vpc_id = aws_vpc.ma.id
}

resource "aws_cloudwatch_log_group" "cw_group" {
    name = "wsc2024-ma-mgmt-log"
}

data "aws_iam_policy_document" "assume_role" {
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
    name = "wsc2024-ma-mgmt-role"
    assume_role_policy = data.aws_iam_policy_document.assume_role.json
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
  name   = "wsc2024-ma-mgmt-role"
  role   = aws_iam_role.role.id
  policy = data.aws_iam_policy_document.policy.json
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
  key_name = "wsc2024"
  public_key = tls_private_key.rsa.public_key_openssh
}

resource "local_file" "keypair" {
  content = tls_private_key.rsa.private_key_pem
  filename = "./wsc2024.pem"
}

resource "aws_eip" "bastion" {
  instance = aws_instance.bastion.id
  associate_with_private_ip = aws_instance.bastion.private_ip
}

resource "random_string" "chungnam_random" {
  length           = 3
  upper   = false
  lower   = false
  numeric  = true
  special = false
}

resource "aws_s3_bucket" "chungnam-object" {
  bucket = "chungnam-object-${random_string.chungnam_random.result}"
  force_destroy = true
}

resource "aws_s3_object" "chungnam-customer" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/customer-app/customer"
  source = "./app/customer-app/customer"
  etag   = filemd5("./app/customer-app/customer")
}

resource "aws_s3_object" "chungnam-customer-Dockerfile" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/customer-app/Dockerfile"
  source = "./app/customer-app/Dockerfile"
  etag   = filemd5("./app/customer-app/Dockerfile")
}

resource "aws_s3_object" "chungnam-order" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/order-app/order"
  source = "./app/order-app/order"
  etag   = filemd5("./app/order-app/order")
}

resource "aws_s3_object" "chungnam-order-Dockerfile" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/order-app/Dockerfile"
  source = "./app/order-app/Dockerfile"
  etag   = filemd5("./app/order-app/Dockerfile")
}

resource "aws_s3_object" "chungnam-product" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/product-app/product"
  source = "./app/product-app/product"
  etag   = filemd5("./app/product-app/product")
}

resource "aws_s3_object" "chungnam-product-Dockerfile" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/product-app/Dockerfile"
  source = "./app/product-app/Dockerfile"
  etag   = filemd5("./app/product-app/Dockerfile")
}

resource "aws_s3_object" "chungnam-secretstore" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/secretstore.yaml"
  source = "./app/yaml/secretstore.yaml"
  etag   = filemd5("./app/yaml/secretstore.yaml")
}

resource "aws_s3_object" "chungnam-externalsecret" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/externalsecret.yaml"
  source = "./app/yaml/externalsecret.yaml"
  etag   = filemd5("./app/yaml/externalsecret.yaml")
}

resource "aws_s3_object" "chungnam-deployment" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/deployment.yaml"
  source = "./app/yaml/deployment.yaml"
  etag   = filemd5("./app/yaml/deployment.yaml")
}

resource "aws_s3_object" "chungnam-service" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/service.yaml"
  source = "./app/yaml/service.yaml"
  etag   = filemd5("./app/yaml/service.yaml")
}

resource "aws_s3_object" "chungnam-ingress" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/ingress.yaml"
  source = "./app/yaml/ingress.yaml"
  etag   = filemd5("./app/yaml/ingress.yaml")
}

resource "aws_s3_object" "chungnam-gatewayclass" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/gate/gatewayclass.yaml"
  source = "./app/yaml/gate/gatewayclass.yaml"
  etag   = filemd5("./app/yaml/gate/gatewayclass.yaml")
}

resource "aws_s3_object" "chungnam-gateway" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/gate/gateway.yaml"
  source = "./app/yaml/gate/gateway.yaml"
  etag   = filemd5("./app/yaml/gate/gateway.yaml")
}

resource "aws_s3_object" "chungnam-targetgroup" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/gate/targetgrouppolicy.yaml"
  source = "./app/yaml/gate/targetgrouppolicy.yaml"
  etag   = filemd5("./app/yaml/gate/targetgrouppolicy.yaml")
}

resource "aws_s3_object" "chungnam-IAMAuth" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/gate/IAMAuthPolicy.yaml"
  source = "./app/yaml/gate/IAMAuthPolicy.yaml"
  etag   = filemd5("./app/yaml/gate/IAMAuthPolicy.yaml")
}

resource "aws_s3_object" "chungnam-route" {
  bucket = aws_s3_bucket.chungnam-object.id
  key    = "/yaml/gate/route.yaml"
  source = "./app/yaml/gate/route.yaml"
  etag   = filemd5("./app/yaml/gate/route.yaml")
}

data "aws_region" "chungnam" {}
data "aws_caller_identity" "chungnam" {}

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
  yum update -y
  yum install -y docker
  yum install -y dos2unix
  systemctl enable --now docker
  usermod -aG docker ec2-user
  usermod -aG docker root
  chmod 666 /var/run/docker.sock
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip awscliv2.zip
  sudo ./aws/install
  ln -s /usr/local/bin/aws /usr/bin/
  ln -s /usr/local/bin/aws_completer /usr/bin/
  yum install -y curl jq
  curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.29.3/2024-04-19/bin/linux/amd64/kubectl
  chmod +x ./kubectl
  mv -f ./kubectl /usr/local/bin/kubectl
  curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
  mv /tmp/eksctl /usr/bin
  curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
  sudo chmod 700 get_helm.sh
  ./get_helm.sh
  sudo mv ./get_helm.sh /usr/local/bin
  sudo dnf install -y mariadb105
  echo "Port 28282" >> /etc/ssh/sshd_config
  systemctl restart sshd
  HOME=/home/ec2-user
  echo "export AWS_DEFAULT_REGION=${data.aws_region.chungnam.name}" >> ~/.bashrc
  echo "export AWS_ACCOUNT_ID=${data.aws_caller_identity.chungnam.account_id}" >> ~/.bashrc
  source ~/.bashrc
  su - ec2-user -c 'aws s3 cp s3://${aws_s3_bucket.chungnam-object.id}/ ~/ --recursive'
  aws ecr get-login-password --region ${data.aws_region.chungnam.name} | docker login --username AWS --password-stdin ${data.aws_caller_identity.chungnam.account_id}.dkr.ecr.${data.aws_region.chungnam.name}.amazonaws.com
  docker build -t ${aws_ecr_repository.customer.repository_url}:latest ~/customer-app/
  docker build -t ${aws_ecr_repository.order.repository_url}:latest ~/order-app/
  docker build -t ${aws_ecr_repository.Product.repository_url}:latest ~/product-app/
  docker push ${aws_ecr_repository.customer.repository_url}:latest
  docker push ${aws_ecr_repository.order.repository_url}:latest
  docker push ${aws_ecr_repository.Product.repository_url}:latest
  aws s3 rm s3://${aws_s3_bucket.chungnam-object.id} --recursive
  aws s3 rb s3://${aws_s3_bucket.chungnam-object.id} --force
  EOF
  tags = {
    Name = "wsc2024-bastion-ec2"
  }
}

## Public Security Group
resource "aws_security_group" "bastion" {
  name = "wsc2024-bastion-sg"
  vpc_id = aws_vpc.ma.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "28282"
    to_port = "28282"
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

  egress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "3306"
    to_port = "3306"
  }

    tags = {
    Name = "wsc2024-bastion-sg"
  }
}

resource "aws_security_group" "lattice" {
  name = "wsc2024-lattice-sg"
  vpc_id = aws_vpc.ma.id

  ingress {
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = "80"
    to_port = "80"
  }

  egress {
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 0
    to_port = 0
  }

    tags = {
    Name = "wsc2024-lattice-sg"
  }
}

## IAM
resource "aws_iam_role" "bastion" {
  name = "wsc2024-bastion-role"
  
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
  name = "wsc2024-ma-mgmt-profile-bastion"
  role = aws_iam_role.bastion.name
}


# OutPut

## VPC
output "ma_vpc" {
  value = aws_vpc.ma.id
}

## Public Subnet
output "public_ma_a" {
  value = aws_subnet.public_a.id
}

output "bastion" {
  value = aws_instance.bastion.id
}

output "bastion-sg" {
  value = aws_security_group.bastion.id
}