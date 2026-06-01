package compliance_framework.require_encrypted_flow_log_format

risk_templates := [{
  "name": "Encrypted VPC flow logs omit required security fields",
  "title": "Encrypted VPC flow log visibility gap",
  "statement": "For encrypted VPCs, the configured flow log format omits required security-relevant fields, reducing visibility into encryption posture and weakening audit and forensic analysis of network activity.",
  "likelihood_hint": "medium",
  "impact_hint": "medium",
  "violation_ids": ["vpc_encrypted_flow_log_format_incomplete"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-778",
      "title": "Insufficient Logging",
      "url": "https://cwe.mitre.org/data/definitions/778.html"
    }
  ],
  "remediation": {
    "title": "Include required security fields in encrypted VPC flow logs",
    "description": "Update the VPC flow log format for encrypted VPCs so it contains all required fields needed to validate encryption-related network telemetry.",
    "tasks": [
      {"title": "Review the current VPC flow log format"},
      {"title": "Add all policy-required fields to the flow log format"},
      {"title": "Confirm the resulting logs expose the required encryption-related telemetry"},
      {"title": "Re-validate log delivery after the format change"}
    ]
  }
}]

vpc_encryption_control := object.get(input.vpc, "EncryptionControl", {})

encrypted_vpc if {
	lower(vpc_encryption_control.Mode) == "enforce"
	lower(vpc_encryption_control.State) == "available"
}

required_flow_log_field[field] if {
	field := data.required_encrypted_vpc_flow_log_fields[_]
}

approved_flow_log_status(status) if {
	approved := data.approved_flow_log_statuses[_]
	status == approved
}

required_traffic_type(traffic_type) if {
	required := data.required_flow_log_traffic_types[_]
	traffic_type == required
}

qualifying_flow_log(flow_log) if {
	approved_flow_log_status(flow_log.FlowLogStatus)
	required_traffic_type(flow_log.TrafficType)
}

flow_log_has_all_required_fields(flow_log) if {
	count({field |
		required_flow_log_field[field]
		not contains(object.get(flow_log, "LogFormat", ""), field)
	}) == 0
}

compliant_flow_log_format if {
	flow_log := input.vpc_context.flow_logs_for_vpc[_]
	qualifying_flow_log(flow_log)
	flow_log_has_all_required_fields(flow_log)
}

violation[{"id": "vpc_encrypted_flow_log_format_incomplete"}] if {
	encrypted_vpc
	count(required_flow_log_field) > 0
	not compliant_flow_log_format
}

skip_reason := "VPC encryption control is not enforced and available" if {
	not encrypted_vpc
}

skip_reason := "required encrypted VPC flow log format fields are not configured" if {
	encrypted_vpc
	count(required_flow_log_field) == 0
}

title := "Encrypted VPC flow logs should include encryption status"
description := sprintf("Flow log format for encrypted VPCs should include required fields: %s", [concat(", ", data.required_encrypted_vpc_flow_log_fields)])
