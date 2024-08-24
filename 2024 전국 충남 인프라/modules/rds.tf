resource "aws_db_parameter_group" "default" {
  name   = "wsc2024-rds-pg"
  family = "aurora-mysql8.0"

  parameter {
    name  = "general_log"
    value = "1"
  }

  parameter {
    name  = "Slow_query_log"
    value = "1"
  }

  parameter {
    name  = "Long_query_time"
    value = "5"
  }

  parameter {
    name  = "log_output"
    value = "TABLE"
  }
}

resource "aws_security_group" "allow_tls" {
  name        = "wsc2024-db-sg"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.storage.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wsc2024-db-sg"
  }
}


resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.allow_tls.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_db_subnet_group" "db" {
    name = "wsc2024-rds-subnet-group"
    subnet_ids = [
        aws_subnet.storage_a.id,
        aws_subnet.storage_b.id
    ]
    
    tags = {
        Name = "wsc2024-rds-subnet-group"
    }
}

resource "aws_rds_cluster" "default" {
  cluster_identifier      = "wsc2024-db-cluster"
  engine                  = "aurora-mysql"
  engine_version          = "8.0.mysql_aurora.3.05.2"
  availability_zones      = ["us-east-1a", "us-east-1b",]
  database_name           = "wsc2024_db"
  master_username         = "admin"
  master_password         = "Skill53##"
  backtrack_window ="14400"
  vpc_security_group_ids  = [aws_security_group.allow_tls.id]
  db_subnet_group_name    = aws_db_subnet_group.db.name
  # db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.default.name
  db_instance_parameter_group_name = aws_db_parameter_group.default.name
  enabled_cloudwatch_logs_exports = ["audit","error","general","slowquery"]
  skip_final_snapshot         = true
  port                        = 3306
  # backup_retention_period = 5
  # preferred_backup_window = "07:00-09:00"
  tags = {
    Name = "wsc2024-db-cluster"
  }
  depends_on = [ aws_db_parameter_group.default ]
  lifecycle {
    ignore_changes = [
      "availability_zones",
      "master_username",
      "cluster_identifier"
    ]
  }
}

resource "aws_rds_cluster_instance" "cluster_instances" {
  count                   = 2
  cluster_identifier      = aws_rds_cluster.default.id
  db_subnet_group_name    = aws_db_subnet_group.db.name
  engine_version          = aws_rds_cluster.default.engine_version
  instance_class          = "db.t3.medium"
  identifier              = "wsc2024-db-cluster-${count.index}"
  engine                  = "aurora-mysql"
  tags = {
    Name = "wsc2024-db-cluster-${count.index}"
  }
  lifecycle {
    ignore_changes = [
      "db_subnet_group_name",
      "engine_version",
      "instance_class"
    ]
  }
}

resource "aws_secretsmanager_secret" "secret" {
  name = "wsc2024/secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret" {
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = jsonencode({
    "username"            = aws_rds_cluster.default.master_username
    "password"            = aws_rds_cluster.default.master_password
    "engine"              = aws_rds_cluster.default.engine
    "host"                = aws_rds_cluster.default.endpoint
    "port"                = aws_rds_cluster.default.port
    "dbClusterIdentifier" = aws_rds_cluster.default.cluster_identifier
    "dbname"              = aws_rds_cluster.default.database_name
    "aws_region"          = "us-east-1"
  })
}