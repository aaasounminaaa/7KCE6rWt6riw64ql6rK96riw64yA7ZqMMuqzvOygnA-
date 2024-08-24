resource "aws_cloudwatch_log_group" "flow_log" {
  name = "wsi-traffic-logs"

  tags = {
    Name = "wsi-traffic-logs"
  }
}

resource "aws_cloudwatch_log_group" "bastion" {
  name = "wsi-bastion-user-logs"

  tags = {
    Name = "wsi-bastion-user-logs"
  }
}

resource "aws_cloudwatch_log_stream" "bastion" {
  name = "wsi-bastion-stream"
  log_group_name = aws_cloudwatch_log_group.bastion.id
}


output "cw_flow_log" {
  value = aws_cloudwatch_log_group.flow_log.id
}

output "cw_bastion" {
  value = aws_cloudwatch_log_group.bastion.id
}

output "cw_stream_bastion" {
  value = aws_cloudwatch_log_stream.bastion.id
}