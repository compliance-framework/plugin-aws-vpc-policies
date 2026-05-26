package compliance_framework.require_encrypted_flow_log_format

vpc_encryption_control := object.get(input.vpc, "EncryptionControl", {})

encrypted_vpc if {
	lower(vpc_encryption_control.Mode) == "enforce"
	lower(vpc_encryption_control.State) == "available"
}

required_flow_log_field[field] if {
	field := data.required_encrypted_vpc_flow_log_fields[_]
}

flow_log_has_all_required_fields(flow_log) if {
	count({field |
		required_flow_log_field[field]
		not contains(object.get(flow_log, "LogFormat", ""), field)
	}) == 0
}

compliant_flow_log_format if {
	flow_log := input.vpc_context.flow_logs_for_vpc[_]
	flow_log_has_all_required_fields(flow_log)
}

violation[{}] if {
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
