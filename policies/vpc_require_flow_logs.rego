package compliance_framework.require_flow_logs

approved_flow_log_status(status) if {
  approved := data.approved_flow_log_statuses[_]
  status == approved
}

required_traffic_type(traffic_type) if {
  required := data.required_flow_log_traffic_types[_]
  traffic_type == required
}

compliant_flow_log if {
  flow_log := input.vpc_context.flow_logs_for_vpc[_]
  approved_flow_log_status(flow_log.FlowLogStatus)
  required_traffic_type(flow_log.TrafficType)
}

violation[{}] if {
  data.require_vpc_flow_logs
  not compliant_flow_log
}

title := "VPC should have active flow logs with required traffic capture"
description := sprintf("VPC flow logs should use approved statuses: %s and capture required traffic types: %s", [concat(", ", data.approved_flow_log_statuses), concat(", ", data.required_flow_log_traffic_types)])
