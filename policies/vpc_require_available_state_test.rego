package compliance_framework.require_available_state

test_no_violation_available_state if {
	count(violation) == 0 with input as {"vpc": {"State": "available"}}
}

test_violation_unapproved_state if {
	count(violation) == 1 with input as {"vpc": {"State": "pending"}}
}

test_no_violation_custom_approved_state if {
	count(violation) == 0 with input as {"vpc": {"State": "pending"}}
		with data.approved_vpc_states as ["pending"] # regal ignore:unresolved-reference
}
