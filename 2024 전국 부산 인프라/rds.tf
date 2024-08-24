resource "aws_security_group" "db" {
  name        = "wsi-RDS-SG"
  description = "wsi-RDS-SG"
  vpc_id      = aws_vpc.main.id

  ingress {
    protocol   = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
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
    Name = "wsi-RDS-SG"
  }
}

resource "aws_vpc_security_group_egress_rule" "control_plane" {
  security_group_id = aws_security_group.control_plane.id

  ip_protocol = "tcp"
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 3306
  to_port     = 3306
}

resource "aws_db_subnet_group" "db" {
  name = "wsi-rds-sg"
  subnet_ids = [
    aws_subnet.data_a.id,
    aws_subnet.data_b.id,
    aws_subnet.data_c.id
  ]

  tags = {
    Name = "wsi-rds-sg"
  }
}

resource "aws_db_option_group" "db" {
  name                     = "wsi-rds-og"
  option_group_description = "wsi-rds-og"
  engine_name              = "mysql"
  major_engine_version     = "8.0"

  tags = {
    Name = "wsi-rds-og"
  }
}
resource "aws_db_parameter_group" "db" {
  name                    = "wsi-rds-pg"
  description             = "wsi-rds-pg"
  family                  = "mysql8.0"

  tags = {
    Name = "wsi-rds-pg"
  }
}

resource "aws_db_instance" "db" {
  identifier             = "wsi-rds-instance"
  instance_class         = "db.t3.micro"
  storage_type           = "gp3"
  engine                 = "mysql"
  db_name                = "skills"
  engine_version         = "8.0"
  allocated_storage      = 20
  username               = "admin"
  password               = "Skill53##"
  port                   = 3306
  skip_final_snapshot    = true
  multi_az               = true
  storage_encrypted      = true
  publicly_accessible    = false
  db_subnet_group_name   = aws_db_subnet_group.db.name
  option_group_name      = aws_db_option_group.db.name
  parameter_group_name   = aws_db_parameter_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  lifecycle {
    ignore_changes = [
      "identifier",
      "instance_class",
      "db_name"
    ]
  }
}

resource "aws_secretsmanager_secret" "db" {
  name = "rds-secret"
}

resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    "username"            = aws_db_instance.db.username,
    "password"            = aws_db_instance.db.password,
    "engine"              = aws_db_instance.db.engine,
    "host"                = aws_db_instance.db.address,
    "port"                = aws_db_instance.db.port,
    "dbname"              = aws_db_instance.db.db_name
    "aws_region"          = "ap-northeast-2"
  })
}

output "security_group" {
  value = aws_security_group.db.id
}

output "subnet_group" {
  value = aws_db_subnet_group.db.id
}

output "parameter_group" {
  value = aws_db_parameter_group.db.id
}

output "rds_instance" {
  value = aws_db_instance.db.id
}

output "rds_secret_manager" {
  value = aws_secretsmanager_secret.db.id
}