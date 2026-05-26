package compliance_framework.require_block_public_access

test_no_violation_block_ingress if {
	count(violation) == 0 with input as {
		"vpc": {"BlockPublicAccessStates": {"InternetGatewayBlockMode": "block-ingress"}}
	}
}

test_no_violation_block_bidirectional if {
	count(violation) == 0 with input as {
		"vpc": {"BlockPublicAccessStates": {"InternetGatewayBlockMode": "block-bidirectional"}}
	}
}

test_violation_off if {
	count(violation) == 1 with input as {
		"vpc": {"BlockPublicAccessStates": {"InternetGatewayBlockMode": "off"}}
	}
}

test_violation_missing_block_public_access_state if {
	count(violation) == 1 with input as {
		"vpc": {}
	}
}

test_no_violation_custom_approved_mode if {
	count(violation) == 0 with input as {
		"vpc": {"BlockPublicAccessStates": {"InternetGatewayBlockMode": "off"}}
	} with data.approved_vpc_block_public_access_modes as ["off"]
}

test_no_violation_when_block_public_access_not_required if {
	count(violation) == 0 with input as {
		"vpc": {}
	} with data.require_vpc_block_public_access as false
}
