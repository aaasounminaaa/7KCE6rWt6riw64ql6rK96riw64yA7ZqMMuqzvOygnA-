variable "create_region" {
  type = string
}

variable "destination_region" {
  type = string
  
}

variable "key_name" {
  type = string
}


# variable "bucket" {
#   type        = string
# }


variable "node_role" {
  type        = string
}

variable "fargate_role" {
  type        = string  
}

# variable "S3_oac" {
#   type        = string  
# }

# variable "eks_host" {
#   type = string
# }

# variable "cluster_role" {
#   type        = string
# }

# variable "default_role" {
#   type        = string
# }

# variable "controller_role" {
#   type        = string
# }