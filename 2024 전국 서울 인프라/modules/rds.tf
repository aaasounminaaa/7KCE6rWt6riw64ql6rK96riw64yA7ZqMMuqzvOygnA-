resource "aws_security_group" "rds_sg" {
    name = "wsi-rds-sg"
    vpc_id =  aws_vpc.main.id

    ingress {
        from_port = 3307
        to_port = 3307
        protocol = "tcp"
        security_groups = [aws_security_group.bastion.id]
    }
    # ingress {
    #     from_port = 3307
    #     to_port = 3307
    #     protocol = "tcp"
    #     # security_groups = [aws_eks_cluster.skills.vpc_config.0.cluster_security_group_id]
    # }
    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
    Name = "wsi-rds-sg"
  }
}

resource "aws_db_subnet_group" "db" {
    name = "wsi-sg"
    subnet_ids = [
        aws_subnet.protect_a.id,
        aws_subnet.protect_b.id
    ]
    
    tags = {
        Name = "wsi-rds-subnet-group"
    }
}

resource "aws_db_parameter_group" "pg" {
    name = "wsi-pg"
    family = "mysql8.0"
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

# resource "aws_kms_key" "rds" {
#   key_usage               = "ENCRYPT_DECRYPT"
#   deletion_window_in_days = 7

#   tags = {
#     Name = "rds-kms"
#   }
# }

# resource "aws_kms_alias" "rds" {
#   target_key_id = aws_kms_key.rds.key_id
#   name          = "alias/rds-kms"
# }

# resource "aws_rds_cluster" "db" {
#     apply_immediately = true
#     cluster_identifier = "wsi-rds-mysql"
#     availability_zones = ["ap-northeast-2a", "ap-northeast-2b","ap-northeast-2c"]
#     db_subnet_group_name = aws_db_subnet_group.db.name
#     db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.db.name
#     db_instance_parameter_group_name = aws_db_parameter_group.pg.name
#     backup_retention_period = 7
#     vpc_security_group_ids = [aws_security_group.rds-sg.id]
#     skip_final_snapshot = true
#     storage_encrypted = true
#     engine = "mysql"
#     kms_key_id = "${var.kms_arn}"
#     database_name = "wsi"
#     master_username = "admin"
#     master_password = "Skill53##"
#     # manage_master_user_password = true
#     # master_user_secret_kms_key_id = aws_kms_key.rds.key_id
#     enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
#     port = "3307"
#     lifecycle {
#         ignore_changes = [
#             replication_source_identifier
#         ]
#     }
# }

# resource "aws_rds_cluster_instance" "db_instances" {
#     count = 2
#     cluster_identifier = aws_rds_cluster.db.id
#     instance_class = "db.m5.xlarge"
#     identifier = "wsi-rds-mysql-${count.index + 1}"
#     engine = "mysql"
#     availability_zone = element(["ap-northeast-2a", "ap-northeast-2b","ap-northeast-2c"], count.index)
#}

resource "aws_db_instance" "mydb" {
  apply_immediately = true
  identifier = "wsi-rds-mysql"
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.m5.xlarge"
  username             = "admin"
  manage_master_user_password = true
#   password             = "Skill53##"
  parameter_group_name = aws_db_parameter_group.pg.name
  multi_az             = true
  storage_type         = "gp2"
  port = "3307"
  backup_retention_period = 7
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.db.name
  skip_final_snapshot = true
  storage_encrypted = true
  db_name = "wsi"
  # Tags
  tags = {
    Name = "wsi-rds-mysql"
  }
  lifecycle {
    ignore_changes = [
      "engine",
      "instance_class",
      "username"
    ]
  }
}

resource "aws_secretsmanager_secret" "db" {
    name = "wsi/secret"
    recovery_window_in_days = 0
    tags = {
        Name = "wsi/secret"
    }
}

resource "aws_secretsmanager_secret_version" "db" {
    secret_id     = aws_secretsmanager_secret.db.id
    secret_string = jsonencode({
        "host" = aws_db_instance.mydb.address
        "port" = aws_db_instance.mydb.port
        "dbname" = aws_db_instance.mydb.db_name
        "aws_region" = "ap-northeast-2"
    })
}

# resource "aws_kms_replica_key" "db" {
#   description = "Multi-Region replica key"
#   deletion_window_in_days = 7
#   primary_key_arn = var.primary_db_kms
# }