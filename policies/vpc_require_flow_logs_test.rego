package compliance_framework.require_flow_logs

test_no_violation_active_all_flow_log if {
  count(violation) == 0 with input as {
    "vpc_context": {
      "flow_logs_for_vpc": [{"FlowLogStatus": "ACTIVE", "TrafficType": "ALL"}]
    }
  }
}

test_violation_missing_flow_logs if {
  count(violation) == 1 with input as {
    "vpc_context": {"flow_logs_for_vpc": []}
  }
}

test_violation_wrong_traffic_type if {
  count(violation) == 1 with input as {
    "vpc_context": {
      "flow_logs_for_vpc": [{"FlowLogStatus": "ACTIVE", "TrafficType": "ACCEPT"}]
    }
  }
}

test_no_violation_when_flow_logs_not_required if {
  count(violation) == 0 with input as {
    "vpc_context": {"flow_logs_for_vpc": []}
  } with data.require_vpc_flow_logs as false
}
