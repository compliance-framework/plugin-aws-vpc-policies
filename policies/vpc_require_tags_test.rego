package compliance_framework.require_tags

test_violation_missing_required_vpc_tags if {
  count(violation) == 1 with input as {
    "vpc": {
      "Tags": [
        {"Key": "Environment", "Value": "prod"},
        {"Key": "Owner", "Value": "platform"}
      ]
    }
  }
}

test_no_violation_required_vpc_tags_present if {
  count(violation) == 0 with input as {
    "vpc": {
      "Tags": [
        {"Key": "environment", "Value": "prod"},
        {"Key": "OWNER", "Value": "platform"},
        {"Key": "compliance", "Value": "soc2"},
        {"Key": "confidentiality", "Value": "internal"}
      ]
    }
  }
}

test_no_violation_custom_required_vpc_tags_present if {
  count(violation) == 0 with input as {
    "vpc": {
      "Tags": [
        {"Key": "cost-center", "Value": "cc-123"}
      ]
    }
  } with data.required_vpc_tags as ["cost-center"]
}
