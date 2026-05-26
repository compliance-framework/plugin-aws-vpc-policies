package compliance_framework.require_encrypted_flow_log_format

encrypted_vpc_input := {
	"vpc": {
		"EncryptionControl": {
			"Mode": "enforce",
			"State": "available"
		}
	},
	"vpc_context": {
		"flow_logs_for_vpc": []
	}
}

test_skip_when_vpc_encryption_control_missing if {
	skip_reason == "VPC encryption control is not enforced and available" with input as {
		"vpc": {},
		"vpc_context": {"flow_logs_for_vpc": []}
	}
}

test_skip_when_vpc_encryption_control_monitor_mode if {
	skip_reason == "VPC encryption control is not enforced and available" with input as {
		"vpc": {"EncryptionControl": {"Mode": "monitor", "State": "available"}},
		"vpc_context": {"flow_logs_for_vpc": []}
	}
}

test_skip_when_vpc_encryption_control_not_available if {
	skip_reason == "VPC encryption control is not enforced and available" with input as {
		"vpc": {"EncryptionControl": {"Mode": "enforce", "State": "enforce-failed"}},
		"vpc_context": {"flow_logs_for_vpc": []}
	}
}

test_skip_when_required_fields_not_configured if {
	skip_reason == "required encrypted VPC flow log format fields are not configured" with input as encrypted_vpc_input with data.required_encrypted_vpc_flow_log_fields as []
}

test_no_violation_encrypted_vpc_flow_log_includes_encryption_status if {
	count(violation) == 0 with input as {
		"vpc": {"EncryptionControl": {"Mode": "enforce", "State": "available"}},
		"vpc_context": {
			"flow_logs_for_vpc": [{"LogFormat": "${version} ${account-id} ${interface-id} ${encryption-status}"}]
		}
	}
}

test_violation_encrypted_vpc_flow_log_missing_encryption_status if {
	count(violation) == 1 with input as {
		"vpc": {"EncryptionControl": {"Mode": "enforce", "State": "available"}},
		"vpc_context": {
			"flow_logs_for_vpc": [{"LogFormat": "${version} ${account-id} ${interface-id}"}]
		}
	}
}

test_violation_encrypted_vpc_without_flow_logs if {
	count(violation) == 1 with input as encrypted_vpc_input
}

test_no_violation_custom_required_field_present if {
	count(violation) == 0 with input as {
		"vpc": {"EncryptionControl": {"Mode": "enforce", "State": "available"}},
		"vpc_context": {
			"flow_logs_for_vpc": [{"LogFormat": "${version} ${flow-direction}"}]
		}
	} with data.required_encrypted_vpc_flow_log_fields as ["flow-direction"]
}
