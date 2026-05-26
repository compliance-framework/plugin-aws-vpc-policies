package compliance_framework.require_available_state

approved_state if {
  state := data.approved_vpc_states[_]
  input.vpc.State == state
}

violation[{}] if {
  not approved_state
}

title := "VPC should be in an approved state"
description := sprintf("VPC state should match one of the approved states: %s", [concat(", ", data.approved_vpc_states)])
