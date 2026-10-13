package compliance_framework.deny_default_vpc

test_violation_default_vpc if {
	count(violation) == 1 with input as {"vpc": {"IsDefault": true}}
}

test_no_violation_non_default_vpc if {
	count(violation) == 0 with input as {"vpc": {"IsDefault": false}}
}

test_no_violation_when_default_vpcs_allowed if {
	count(violation) == 0 with input as {"vpc": {"IsDefault": true}}
		with data.allow_default_vpcs as true # regal ignore:unresolved-reference
}
