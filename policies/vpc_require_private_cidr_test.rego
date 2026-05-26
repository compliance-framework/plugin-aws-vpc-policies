package compliance_framework.require_private_cidr

test_no_violation_private_vpc_cidr if {
  count(violation) == 0 with input as {
    "vpc": {"CidrBlock": "10.20.0.0/16"}
  }
}

test_violation_unapproved_vpc_cidr if {
  count(violation) == 1 with input as {
    "vpc": {"CidrBlock": "100.64.0.0/16"}
  }
}

test_violation_unapproved_associated_cidr if {
  count(violation) == 1 with input as {
    "vpc": {
      "CidrBlock": "10.20.0.0/16",
      "CidrBlockAssociationSet": [{"CidrBlock": "100.64.0.0/16"}]
    }
  }
}

test_no_violation_custom_approved_cidr if {
  count(violation) == 0 with input as {
    "vpc": {"CidrBlock": "100.64.0.0/16"}
  } with data.approved_vpc_cidr_blocks as ["100.64.0.0/10"]
}
