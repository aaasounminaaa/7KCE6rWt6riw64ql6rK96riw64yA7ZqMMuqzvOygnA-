data "aws_ec2_managed_prefix_list" "cloudfront" {
 name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "alb" {
  name        = "wsi-app-alb-sg"
  description = "wsi-app-alb-sg"
  vpc_id      = aws_vpc.main.id

  ingress {
    protocol     = "tcp"
    from_port    = 80
    to_port      = 80
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront.id]
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

resource "aws_security_group" "ep" {
  name        = "wsi-EP-SG"
  description = "wsi-EP-SG"
  vpc_id      = aws_vpc.main.id

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
    Name = "wsi-EP-SG"
  }
}

output "alb" {
    value = aws_security_group.alb.id
}

output "ep" {
  value = aws_security_group.ep.id
}