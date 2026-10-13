package compliance_framework.require_network_address_usage_metrics

network_address_usage_metrics_enabled if {
	input.vpc_context.attributes.enable_network_address_usage_metrics == true
}

violation[{}] if {
	data.require_vpc_network_address_usage_metrics # regal ignore:unresolved-reference
	not network_address_usage_metrics_enabled
}

title := "VPC network address usage metrics should be enabled"
description := "VPC network address usage metrics should be enabled where policy requires visibility into IP address usage"
