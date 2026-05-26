package compliance_framework.require_encryption_control

vpc_encryption_control := object.get(input.vpc, "EncryptionControl", {})

approved_mode if {
	mode := data.approved_vpc_encryption_control_modes[_]
	vpc_encryption_control.Mode == mode
}

approved_state if {
	state := data.approved_vpc_encryption_control_states[_]
	vpc_encryption_control.State == state
}

allowed_exclusion(exclusion_name) if {
	allowed := data.allowed_vpc_encryption_control_exclusions[_]
	allowed == exclusion_name
}

enabled_exclusion[exclusion_name] if {
	exclusions := object.get(vpc_encryption_control, "ResourceExclusions", {})
	exclusion := exclusions[exclusion_name]
	lower(exclusion.State) == "enabled"
}

unapproved_enabled_exclusion[exclusion_name] if {
	enabled_exclusion[exclusion_name]
	not allowed_exclusion(exclusion_name)
}

compliant_encryption_control if {
	approved_mode
	approved_state
	count(unapproved_enabled_exclusion) == 0
}

violation[{}] if {
	data.require_vpc_encryption_control
	not compliant_encryption_control
}

title := "VPC encryption control should use an approved mode"
description := sprintf("VPC encryption control should exist, use approved modes: %s, approved states: %s, and only have approved enabled resource exclusions: %s", [concat(", ", data.approved_vpc_encryption_control_modes), concat(", ", data.approved_vpc_encryption_control_states), concat(", ", data.allowed_vpc_encryption_control_exclusions)])
