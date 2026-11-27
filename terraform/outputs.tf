output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "bucket_arn" {
  value = aws_s3_bucket.data.arn
}

output "function_name" {
  value = aws_lambda_function.resolver.function_name
}
