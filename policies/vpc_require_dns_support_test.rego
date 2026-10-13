package compliance_framework.require_dns_support

test_no_violation_dns_support_enabled if {
	count(violation) == 0 with input as {"vpc_context": {"attributes": {"enable_dns_support": true}}}
}

test_violation_dns_support_disabled if {
	count(violation) == 1 with input as {"vpc_context": {"attributes": {"enable_dns_support": false}}}
}

test_no_violation_dns_support_not_required if {
	count(violation) == 0 with input as {"vpc_context": {"attributes": {"enable_dns_support": false}}}
		with data.require_dns_support as false # regal ignore:unresolved-reference
}
