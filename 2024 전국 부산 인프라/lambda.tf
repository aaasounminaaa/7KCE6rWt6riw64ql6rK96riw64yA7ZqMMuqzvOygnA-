# Assume Role Policy Document
data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com", "edgelambda.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

# IAM Role
resource "aws_iam_role" "lambda" {
  name               = "lambda-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

resource "aws_iam_role_policy_attachment" "s3" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
resource "aws_iam_role_policy_attachment" "cf" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/CloudFrontFullAccess"
}
resource "aws_iam_role_policy_attachment" "cw" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchFullAccess"
}

data "archive_file" "lambda" {
  type        = "zip"
  source_file = "./src/lambda_function.py"
  output_path = "lambda_function_payload.zip"
}

resource "aws_lambda_function" "lambda" {
    provider = aws.us-east-1
    
    filename = "lambda_function_payload.zip"
    function_name = "wsi-function"
    role = aws_iam_role.lambda.arn
    handler = "lambda_function.lambda_handler"
    timeout = "30"
    source_code_hash = data.archive_file.lambda.output_base64sha256
    runtime = "python3.12"
    publish = true
}
output "lambda" {
    value = aws_lambda_function.lambda.arn
}