package compliance_framework.require_approved_dhcp_options

approved_dhcp_options_id if {
  approved := data.approved_vpc_dhcp_options_ids[_]
  input.vpc.DhcpOptionsId == approved
}

violation[{}] if {
  count(data.approved_vpc_dhcp_options_ids) > 0
  not approved_dhcp_options_id
}

skip_reason := "approved VPC DHCP options IDs are not configured" if {
  count(data.approved_vpc_dhcp_options_ids) == 0
}

title := "VPC should use approved DHCP options"
description := sprintf("VPC DHCP options should match one of the approved DHCP options set IDs: %s", [concat(", ", data.approved_vpc_dhcp_options_ids)])
