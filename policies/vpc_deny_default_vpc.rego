package compliance_framework.deny_default_vpc

default_vpc if {
	input.vpc.IsDefault == true
}

violation[{}] if {
	not data.allow_default_vpcs # regal ignore:unresolved-reference
	default_vpc
}

title := "VPC should not be the default VPC"
description := "Default VPCs are automatically created by AWS and should not be used for managed workload network boundaries"
