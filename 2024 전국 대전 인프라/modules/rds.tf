resource "aws_security_group" "allow_tls" {
  name        = "hrdkorea-db-sg"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "hrdkorea-db-sg"
  }
}



resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv4         = aws_vpc.main.cidr_block
  from_port         = 3409
  ip_protocol       = "tcp"
  to_port           = 3409
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_db_subnet_group" "db" {
    name = "hrdkorea-rds-sg"
    subnet_ids = [
        aws_subnet.protect_a.id,
        aws_subnet.protect_b.id
    ]
    
    tags = {
        Name = "hrdkorea-sg"
    }
}

resource "aws_rds_cluster_parameter_group" "db" {
  name        = "hrdkorea-rds-cpg"
  description = "hrdkorea-rds-cpg"
  family      = "aurora-mysql8.0"

  parameter {
    name  = "time_zone"
    value = "Asia/Seoul"
  }
  tags = {
    Name = "hrdkorea-rds-cpg"
  }
}

resource "aws_db_parameter_group" "db" {
  name        = "hrdkorea-rds-pg"
  description = "hrdkorea-rds-pg"
  family      = "aurora-mysql8.0"

  tags = {
    Name = "hrdkorea-rds-pg"
  }
}

output "cluster_parameter_group"{
    value = aws_rds_cluster_parameter_group.db.name
}

output "paramter_group"{
    value = aws_db_parameter_group.db.name
}


output "subnet_group" {
    value = aws_db_subnet_group.db.id
}

output "security_group"{
    value = aws_security_group.allow_tls.id
}