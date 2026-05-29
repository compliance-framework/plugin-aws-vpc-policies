package compliance_framework.require_encryption_control

risk_templates := [{
  "name": "VPC encryption control is not compliant",
  "title": "VPC traffic encryption enforcement gap",
  "statement": "VPC encryption control is missing, in an unapproved mode or state, or contains unapproved enabled exclusions, weakening enforcement of expected encryption protections across the VPC boundary.",
  "likelihood_hint": "medium",
  "impact_hint": "high",
  "violation_ids": ["vpc_encryption_control_not_compliant"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-311",
      "title": "Missing Encryption of Sensitive Data",
      "url": "https://cwe.mitre.org/data/definitions/311.html"
    }
  ],
  "remediation": {
    "title": "Align VPC encryption control with approved policy",
    "description": "Enable VPC encryption control in an approved mode and state, and remove any enabled exclusions that are not explicitly approved.",
    "tasks": [
      {"title": "Enable VPC encryption control if it is missing"},
      {"title": "Set the encryption control mode and state to approved values"},
      {"title": "Disable unapproved enabled resource exclusions"},
      {"title": "Review any remaining exclusions to confirm they are explicitly allowed and justified"}
    ]
  }
}]

vpc_encryption_control := object.get(input.vpc, "EncryptionControl", {})

approved_mode if {
	mode := data.approved_vpc_encryption_control_modes[_]
	vpc_encryption_control.Mode == mode
}

approved_state if {
	state := data.approved_vpc_encryption_control_states[_]
	vpc_encryption_control.State == state
}

allowed_exclusion(exclusion_name) if {
	allowed := data.allowed_vpc_encryption_control_exclusions[_]
	allowed == exclusion_name
}

enabled_exclusion[exclusion_name] if {
	exclusions := object.get(vpc_encryption_control, "ResourceExclusions", {})
	exclusion := exclusions[exclusion_name]
	lower(exclusion.State) == "enabled"
}

unapproved_enabled_exclusion[exclusion_name] if {
	enabled_exclusion[exclusion_name]
	not allowed_exclusion(exclusion_name)
}

compliant_encryption_control if {
	approved_mode
	approved_state
	count(unapproved_enabled_exclusion) == 0
}

violation[{"id": "vpc_encryption_control_not_compliant"}] if {
	data.require_vpc_encryption_control
	not compliant_encryption_control
}

title := "VPC encryption control should use an approved mode"
description := sprintf("VPC encryption control should exist, use approved modes: %s, approved states: %s, and only have approved enabled resource exclusions: %s", [concat(", ", data.approved_vpc_encryption_control_modes), concat(", ", data.approved_vpc_encryption_control_states), concat(", ", data.allowed_vpc_encryption_control_exclusions)])
