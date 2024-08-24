resource "aws_security_group" "db" {
    name        = "wsi-rds-SG"
    description = "wsi-rds-SG"
    vpc_id      = aws_vpc.prod.id

    ingress {
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
        from_port = "3306"
        to_port = "3306"
    }
    
    lifecycle {
        ignore_changes = [
        ingress,
        egress
        ]
    }
  tags = {
    Name = "wsi-rds-SG"
  }
}

resource "aws_vpc_security_group_egress_rule" "bastion" {
  security_group_id = aws_security_group.bastion.id

  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 3306
  to_port     = 3306
}


resource "aws_db_subnet_group" "db" {
    name = "wsi-rds-sg"
    subnet_ids = [
        aws_subnet.protect_a.id,
        aws_subnet.protect_c.id
    ]
    
    tags = {
        Name = "wsi-rds-sg"
    }
}
resource "aws_rds_cluster_parameter_group" "db" {
  name        = "wsi-rds-cpg"
  description = "wsi-rds-cpg"
  family      = "aurora-mysql8.0"

  parameter {
    name  = "time_zone"
    value = "Asia/Seoul"
  }

  tags = {
    Name = "wsi-rds-cpg"
  }
}

resource "aws_db_parameter_group" "db" {
  name        = "wsi-rds-pg"
  description = "wsi-rds-pg"
  family      = "aurora-mysql8.0"

  tags = {
    Name = "wsi-rds-pg"
  }
}
resource "aws_rds_cluster" "db" {
  cluster_identifier          = "wsc-prod-db-cluster"
  database_name               = "wscdb"
  availability_zones          = ["ap-northeast-2a", "ap-northeast-2c"]
  db_subnet_group_name        = aws_db_subnet_group.db.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.db.name
  db_instance_parameter_group_name = aws_db_parameter_group.db.name
  master_username             = "skill"
  master_password             = "Skill53##"
  skip_final_snapshot         = true
  storage_encrypted           = true
  engine                      = "aurora-mysql"

  tags = {
    Name = "wsc-prod-db-cluster"
  }
  lifecycle {
    ignore_changes = [
      "availability_zones",
      "db_cluster_parameter_group_name",
      "db_cluster_parameter_group_name"
    ]
  }
}

resource "aws_rds_cluster_instance" "db" {
  count                   = 1
  cluster_identifier      = aws_rds_cluster.db.id
  db_subnet_group_name    = aws_db_subnet_group.db.name
  instance_class          = "db.t3.medium"
  identifier              = "wsc-prod-db-cluster-${count.index}"
  engine                  = "aurora-mysql"

  tags = {
    Name = "wsi-aurora-mysql-${count.index + 1}"
  }
  lifecycle {
    ignore_changes = [
      "db_subnet_group_name",
      "instance_class",
      "identifier"
    ]
  }
}

resource "aws_secretsmanager_secret" "db" {
  name = "wsc2024/secret"
}

data "aws_region" "current" {}
resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    "username"           = aws_rds_cluster.db.master_username
    "password"           = aws_rds_cluster.db.master_password
    "engine"             = aws_rds_cluster.db.engine
    "host"               = aws_rds_cluster.db.endpoint
    "port"               = aws_rds_cluster.db.port
    "dbClusterIdentifier" = aws_rds_cluster.db.cluster_identifier
    "dbname"             = aws_rds_cluster.db.database_name
    "aws_region"             = "${data.aws_region.current.name}"
  })
}