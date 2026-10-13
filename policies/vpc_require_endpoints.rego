package compliance_framework.require_endpoints

required_service[service] if {
	service := data.required_vpc_endpoint_services[_] # regal ignore:unresolved-reference
}

approved_endpoint_state(state) if {
	approved := data.approved_vpc_endpoint_states[_] # regal ignore:unresolved-reference
	state == approved
}

endpoint_matches_service(endpoint, service) if {
	endpoint.ServiceName == service
}

endpoint_matches_service(endpoint, service) if {
	endswith(endpoint.ServiceName, sprintf(".%s", [service]))
}

service_endpoint_present(service) if {
	endpoint := input.vpc_context.vpc_endpoints_for_vpc[_]
	endpoint_matches_service(endpoint, service)
	approved_endpoint_state(endpoint.State)
}

missing_service[service] if {
	required_service[service]
	not service_endpoint_present(service)
}

violation[{}] if {
	count(required_service) > 0
	count(missing_service) > 0
}

skip_reason := "required VPC endpoint services are not configured" if {
	count(required_service) == 0
}

title := "VPC should have required VPC endpoints"
description := sprintf("VPC endpoints should exist in approved states: %s for required services: %s", [concat(", ", data.approved_vpc_endpoint_states), concat(", ", data.required_vpc_endpoint_services)]) # regal ignore:unresolved-reference
