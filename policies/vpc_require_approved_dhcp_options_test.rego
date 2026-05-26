package compliance_framework.require_approved_dhcp_options

test_skip_when_approved_dhcp_options_not_configured if {
  skip_reason == "approved VPC DHCP options IDs are not configured" with input as {
    "vpc": {"DhcpOptionsId": "dopt-123"}
  }
}

test_no_violation_approved_dhcp_options if {
  count(violation) == 0 with input as {
    "vpc": {"DhcpOptionsId": "dopt-123"}
  } with data.approved_vpc_dhcp_options_ids as ["dopt-123"]
}

test_violation_unapproved_dhcp_options if {
  count(violation) == 1 with input as {
    "vpc": {"DhcpOptionsId": "dopt-456"}
  } with data.approved_vpc_dhcp_options_ids as ["dopt-123"]
}
