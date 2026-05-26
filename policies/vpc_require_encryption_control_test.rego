package compliance_framework.require_encryption_control

test_no_violation_enforce_available_without_exclusions if {
	count(violation) == 0 with input as {
		"vpc": {
			"EncryptionControl": {
				"Mode": "enforce",
				"State": "available",
				"ResourceExclusions": {
					"InternetGateway": {"State": "disabled"},
					"NatGateway": {"State": "disabled"}
				}
			}
		}
	}
}

test_violation_missing_encryption_control if {
	count(violation) == 1 with input as {
		"vpc": {}
	}
}

test_violation_unapproved_mode if {
	count(violation) == 1 with input as {
		"vpc": {
			"EncryptionControl": {"Mode": "monitor", "State": "available"}
		}
	}
}

test_violation_unapproved_state if {
	count(violation) == 1 with input as {
		"vpc": {
			"EncryptionControl": {"Mode": "enforce", "State": "enforce-failed"}
		}
	}
}

test_violation_unapproved_enabled_exclusion if {
	count(violation) == 1 with input as {
		"vpc": {
			"EncryptionControl": {
				"Mode": "enforce",
				"State": "available",
				"ResourceExclusions": {
					"InternetGateway": {"State": "enabled"}
				}
			}
		}
	}
}

test_no_violation_allowed_enabled_exclusion if {
	count(violation) == 0 with input as {
		"vpc": {
			"EncryptionControl": {
				"Mode": "enforce",
				"State": "available",
				"ResourceExclusions": {
					"InternetGateway": {"State": "enabled"}
				}
			}
		}
	} with data.allowed_vpc_encryption_control_exclusions as ["InternetGateway"]
}

test_no_violation_monitor_when_approved if {
	count(violation) == 0 with input as {
		"vpc": {
			"EncryptionControl": {"Mode": "monitor", "State": "available"}
		}
	} with data.approved_vpc_encryption_control_modes as ["monitor", "enforce"]
}

test_no_violation_when_encryption_control_not_required if {
	count(violation) == 0 with input as {
		"vpc": {}
	} with data.require_vpc_encryption_control as false
}
