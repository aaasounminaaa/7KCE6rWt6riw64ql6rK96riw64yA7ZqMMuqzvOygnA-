resource "aws_iam_role" "lambda" {
  name = "lambda-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

resource "aws_lambda_function" "lambda" {
  function_name = "skills-rds-secret-function"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.12"
  filename      = "./src/secretmanger-lambda-function.zip"
  source_code_hash = filebase64sha256("./src/secretmanger-lambda-function.zip")  
  role          = aws_iam_role.lambda.arn
}
resource "aws_lambda_permission" "allow_secrets_manager" {
  statement_id  = "AllowSecretsManagerInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda.function_name
  principal     = "secretsmanager.amazonaws.com"
  source_arn    = "${aws_secretsmanager_secret.secret.id}"
}