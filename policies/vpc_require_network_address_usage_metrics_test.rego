package compliance_framework.require_network_address_usage_metrics

test_no_violation_network_address_usage_metrics_enabled if {
	count(violation) == 0 with input as {"vpc_context": {"attributes": {"enable_network_address_usage_metrics": true}}}
}

test_violation_network_address_usage_metrics_disabled if {
	count(violation) == 1 with input as {"vpc_context": {"attributes": {"enable_network_address_usage_metrics": false}}}
}

test_violation_network_address_usage_metrics_missing if {
	count(violation) == 1 with input as {"vpc_context": {"attributes": {}}}
}

test_no_violation_network_address_usage_metrics_not_required if {
	count(violation) == 0 with input as {"vpc_context": {"attributes": {"enable_network_address_usage_metrics": false}}}
		with data.require_vpc_network_address_usage_metrics as false # regal ignore:unresolved-reference
}
