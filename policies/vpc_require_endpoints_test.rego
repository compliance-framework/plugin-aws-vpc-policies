package compliance_framework.require_endpoints

test_skip_when_required_endpoints_not_configured if {
	skip_reason == "required VPC endpoint services are not configured" with input as {"vpc_context": {"vpc_endpoints_for_vpc": []}}
}

test_no_violation_required_endpoint_suffix_present if {
	count(violation) == 0 with input as {"vpc_context": {"vpc_endpoints_for_vpc": [{"ServiceName": "com.amazonaws.eu-west-2.s3", "State": "available"}]}}
		with data.required_vpc_endpoint_services as ["s3"] # regal ignore:unresolved-reference
}

test_no_violation_required_endpoint_full_name_present if {
	count(violation) == 0 with input as {"vpc_context": {"vpc_endpoints_for_vpc": [{"ServiceName": "com.amazonaws.eu-west-2.logs", "State": "available"}]}}
		with data.required_vpc_endpoint_services as ["com.amazonaws.eu-west-2.logs"] # regal ignore:unresolved-reference
}

test_violation_required_endpoint_missing if {
	count(violation) == 1 with input as {"vpc_context": {"vpc_endpoints_for_vpc": []}}
		with data.required_vpc_endpoint_services as ["s3"] # regal ignore:unresolved-reference
}

test_violation_required_endpoint_wrong_state if {
	count(violation) == 1 with input as {"vpc_context": {"vpc_endpoints_for_vpc": [{"ServiceName": "com.amazonaws.eu-west-2.s3", "State": "pending"}]}}
		with data.required_vpc_endpoint_services as ["s3"] # regal ignore:unresolved-reference
}
