### Module 선언
module "usa" {
    source = "./modules"
    # kms_arn = aws_kms_key.example.arn
    create_region = "us-east-1"
    providers = {
      aws = aws.usa
    }
}