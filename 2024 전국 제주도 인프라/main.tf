### Module 선언
module "seoul" {
    source = "./modules"
    create_region = "ap-northeast-2"
    providers = {
      aws = aws.seoul
    }
}
### Module 선언
# module "special" {
#     source = "./RDS&&EKS"
#     bastion-iam = module.seoul.bastion-iam
#     workload-a = module.seoul.prod_workload_a
#     workload-c = module.seoul.prod_workload_c
#     prod_vpc = module.seoul.aws_prod_vpc
#     protect_a=module.seoul.protect_a
#     protect_c=module.seoul.protect_c
#     providers = {
#       aws = aws.special
#     }
# }