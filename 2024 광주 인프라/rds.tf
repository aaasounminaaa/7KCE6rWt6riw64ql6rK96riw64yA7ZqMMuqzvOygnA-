resource "aws_security_group" "db" {
  name        = "skills-RDS-SG"
  description = "skills-RDS-SG"
  vpc_id      = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    from_port  = 3306
    to_port    = 3306
  }

  egress {
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "skills-RDS-SG"
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
  name = "skills-rds-sg"
  subnet_ids = [
    aws_subnet.data_a.id,
    aws_subnet.data_b.id
  ]

  tags = {
    Name = "skills-rds-sg"
  }
}

resource "aws_rds_cluster_parameter_group" "db" {
  name        = "skills-rds-cpg"
  description = "skills-rds-cpg"
  family      = "aurora-mysql8.0"

  parameter {
    name  = "time_zone"
    value = "Asia/Seoul"
  }

  tags = {
    Name = "skills-rds-cpg"
  }
}

resource "aws_db_parameter_group" "db" {
  name        = "skills-rds-pg"
  description = "skills-rds-pg"
  family      = "aurora-mysql8.0"

  tags = {
    Name = "skills-rds-pg"
  }
}

resource "aws_kms_key" "rds" {
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7

  tags = {
    Name = "rds-kms"
  }
}

resource "aws_kms_alias" "rds" {
  target_key_id = aws_kms_key.rds.key_id
  name          = "alias/rds-kms"
}

resource "aws_rds_cluster" "db" {
  cluster_identifier          = "skills-aurora-mysql"
  database_name               = "skills"
  availability_zones          = ["ap-northeast-2a", "ap-northeast-2b"]
  db_subnet_group_name        = aws_db_subnet_group.db.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.db.name
  db_instance_parameter_group_name = aws_db_parameter_group.db.name
  kms_key_id                  = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports  = ["audit", "error"]
  engine                      = "aurora-mysql"
  engine_mode                 = "provisioned"
  master_username             = "admin"
  master_password             = "Skill53##"
  skip_final_snapshot         = true
  storage_encrypted           = true
  port                        = 3306

  serverlessv2_scaling_configuration {
    min_capacity = 2
    max_capacity = 8
  }

  tags = {
    Name = "skills-aurora-mysql"
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
  engine_version          = aws_rds_cluster.db.engine_version
  instance_class          = "db.serverless"
  identifier              = "skills-aurora-mysql-${count.index}"
  engine                  = "aurora-mysql"

  tags = {
    Name = "skills-aurora-mysql-${count.index}"
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
  name = "skills-rds-secret"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "secret" {
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = jsonencode({
    "username"            = aws_rds_cluster.db.master_username
    "password"            = aws_rds_cluster.db.master_password
    "engine"              = aws_rds_cluster.db.engine
    "host"                = aws_rds_cluster.db.endpoint
    "port"                = aws_rds_cluster.db.port
    "dbClusterIdentifier" = aws_rds_cluster.db.cluster_identifier
    "dbname"              = aws_rds_cluster.db.database_name
    "aws_region"          = "ap-northeast-2"
  })
}

resource "aws_secretsmanager_secret_rotation" "secret" {
  secret_id           = aws_secretsmanager_secret.secret.id
  rotation_lambda_arn = aws_lambda_function.lambda.arn

  rotation_rules {
    automatically_after_days = 3
  }
}

output "security_group" {
  value = aws_security_group.db.id
}

output "subnet_group" {
  value = aws_db_subnet_group.db.id
}

output "cluster_parameter_group" {
  value = aws_rds_cluster_parameter_group.db.id
}

output "parameter_group" {
  value = aws_db_parameter_group.db.id
}

output "rds_kms" {
  value = aws_kms_key.rds.id
}

output "rds_cluster" {
  value = aws_rds_cluster.db.id
}

output "rds_secret_manager" {
  value = aws_secretsmanager_secret.secret.id
}