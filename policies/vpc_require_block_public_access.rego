package compliance_framework.require_block_public_access

vpc_block_public_access := object.get(input.vpc, "BlockPublicAccessStates", {})

approved_block_public_access_mode if {
	mode := data.approved_vpc_block_public_access_modes[_]
	vpc_block_public_access.InternetGatewayBlockMode == mode
}

violation[{}] if {
	data.require_vpc_block_public_access
	not approved_block_public_access_mode
}

title := "VPC block public access should use an approved mode"
description := sprintf("VPC Block Public Access should use an approved internet gateway block mode: %s", [concat(", ", data.approved_vpc_block_public_access_modes)])
