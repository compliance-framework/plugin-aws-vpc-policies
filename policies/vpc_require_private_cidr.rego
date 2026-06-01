package compliance_framework.require_private_cidr

vpc_cidr[cidr] if {
  cidr := input.vpc.CidrBlock
  cidr != ""
}

active_cidr_association(association) if {
  association.CidrBlockState.State == "associated"
}

vpc_cidr[cidr] if {
  association := input.vpc.CidrBlockAssociationSet[_]
  active_cidr_association(association)
  cidr := association.CidrBlock
  cidr != ""
}

approved_cidr(cidr) if {
  approved := data.approved_vpc_cidr_blocks[_]
  net.cidr_contains(approved, cidr)
}

violation[{}] if {
  vpc_cidr[cidr]
  not approved_cidr(cidr)
}

title := "VPC CIDR blocks should be within approved ranges"
description := sprintf("VPC IPv4 CIDR blocks should be contained within approved CIDR ranges: %s", [concat(", ", data.approved_vpc_cidr_blocks)])
