package compliance_framework.require_dns_hostnames

dns_hostnames_enabled if {
  input.vpc_context.attributes.enable_dns_hostnames == true
}

violation[{}] if {
  data.require_dns_hostnames
  not dns_hostnames_enabled
}

title := "VPC DNS hostnames should be enabled"
description := "VPC DNS hostnames should be enabled where policy requires DNS names for resources launched in the VPC"
