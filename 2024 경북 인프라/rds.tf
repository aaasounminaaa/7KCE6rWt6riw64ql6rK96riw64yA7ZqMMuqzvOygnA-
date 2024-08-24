resource "aws_security_group" "db" {
  name        = "wsi-RDS-SG"
  description = "wsi-RDS-SG"
  vpc_id      = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    from_port  = 4000
    to_port    = 4000
  }

  egress {
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "wsi-RDS-SG"
  }
}

resource "aws_vpc_security_group_egress_rule" "bastion" {
  security_group_id = aws_security_group.bastion.id

  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 4000
  to_port     = 4000
}

resource "aws_db_subnet_group" "db" {
  name = "wsi-rds-sg"
  subnet_ids = [
    aws_subnet.data_a.id,
    aws_subnet.data_b.id
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
  cluster_identifier          = "wsi-aurora-mysql"
  database_name               = "dev"
  availability_zones          = ["ap-northeast-2a", "ap-northeast-2b"]
  db_subnet_group_name        = aws_db_subnet_group.db.name
  vpc_security_group_ids      = [aws_security_group.db.id]
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.db.name
  db_instance_parameter_group_name = aws_db_parameter_group.db.name
  kms_key_id                  = aws_kms_key.rds.arn
  enabled_cloudwatch_logs_exports  = ["audit", "error"]
  engine                      = "aurora-mysql"
  master_username             = "admin"
  master_password             = "Skill53##"
  skip_final_snapshot         = true
  storage_encrypted           = true
  port                        = 4000

  tags = {
    Name = "wsi-aurora-mysql"
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
  identifier              = "wsi-aurora-mysql-${count.index}"
  engine                  = "aurora-mysql"

  tags = {
    Name = "wsi-aurora-mysql-${count.index}"
  }
  lifecycle {
    ignore_changes = [
      "db_subnet_group_name",
      "instance_class",
      "identifier"
    ]
  }
}

resource "aws_secretsmanager_secret" "customer" {
  name = "customer"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "product" {
  name = "product"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret" "order" {
  name = "order"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "customer" {
  secret_id     = aws_secretsmanager_secret.customer.id
  secret_string = jsonencode({
    "username"            = aws_rds_cluster.db.master_username
    "password"            = aws_rds_cluster.db.master_password
    "engine"              = aws_rds_cluster.db.engine
    "host"                = aws_rds_cluster.db.endpoint
    "port"                = aws_rds_cluster.db.port
    "dbClusterIdentifier" = aws_rds_cluster.db.cluster_identifier
    "dbname"              = aws_rds_cluster.db.database_name
  })
}

resource "aws_secretsmanager_secret_version" "product" {
  secret_id     = aws_secretsmanager_secret.product.id
  secret_string = jsonencode({
    "username"            = aws_rds_cluster.db.master_username
    "password"            = aws_rds_cluster.db.master_password
    "engine"              = aws_rds_cluster.db.engine
    "host"                = aws_rds_cluster.db.endpoint
    "port"                = aws_rds_cluster.db.port
    "dbClusterIdentifier" = aws_rds_cluster.db.cluster_identifier
    "dbname"              = aws_rds_cluster.db.database_name
  })
}

resource "aws_secretsmanager_secret_version" "order" {
  secret_id     = aws_secretsmanager_secret.order.id
  secret_string = jsonencode({
    "aws_region"            = "ap-northeast-2"
  })
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

output "customer_rds_secret_manager" {
  value = aws_secretsmanager_secret.customer.id
}

output "product_rds_secret_manager" {
  value = aws_secretsmanager_secret.product.id
}

output "order_rds_secret_manager" {
  value = aws_secretsmanager_secret.order.id
}