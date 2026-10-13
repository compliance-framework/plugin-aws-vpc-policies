package compliance_framework.require_dns_support

dns_support_enabled if {
	input.vpc_context.attributes.enable_dns_support == true
}

violation[{}] if {
	data.require_dns_support # regal ignore:unresolved-reference
	not dns_support_enabled
}

title := "VPC DNS support should be enabled"
description := "VPC DNS support should be enabled so AWS-provided DNS resolution is available within the VPC"
