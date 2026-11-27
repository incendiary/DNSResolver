variable "name_prefix" {
  description = "Prefix for the DNSResolver Lambda and IAM resources."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name for versioned DNS input and run output."
  type        = string
}

variable "package_file" {
  description = "Absolute path to the locally built DNSResolver Lambda ZIP."
  type        = string
}
