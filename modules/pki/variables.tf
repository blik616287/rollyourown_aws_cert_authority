variable "prefix" {
  description = "namespace prefix for the cert authority"
  type        = string
  default     = "default"
}

variable "lambda" {
  description = "Output specifying the ciphernest lambda function"
  type = object({
    name = string
    role = string
    arn  = string
  })
}
