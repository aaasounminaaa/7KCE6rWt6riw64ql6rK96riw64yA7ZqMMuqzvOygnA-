resource "aws_security_group" "controlplan" {
  name = "skills-EKS-ControlPlan-SG"
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
    Name = "skills-controlplan-SG"
  }
}

output "controlplan" {
    value = aws_security_group.controlplan.id
}