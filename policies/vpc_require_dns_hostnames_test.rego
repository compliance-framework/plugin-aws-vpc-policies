package compliance_framework.require_dns_hostnames

test_no_violation_dns_hostnames_enabled if {
	count(violation) == 0 with input as {"vpc_context": {"attributes": {"enable_dns_hostnames": true}}}
}

test_violation_dns_hostnames_disabled if {
	count(violation) == 1 with input as {"vpc_context": {"attributes": {"enable_dns_hostnames": false}}}
}

test_no_violation_dns_hostnames_not_required if {
	count(violation) == 0 with input as {"vpc_context": {"attributes": {"enable_dns_hostnames": false}}}
		with data.require_dns_hostnames as false # regal ignore:unresolved-reference
}
