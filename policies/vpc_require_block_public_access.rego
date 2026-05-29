package compliance_framework.require_block_public_access

risk_templates := [{
  "name": "VPC block public access is not enforced",
  "title": "VPC internet boundary exposure risk",
  "statement": "The VPC Block Public Access setting is missing or uses an unapproved mode, increasing the chance that internet gateway paths expose workloads or network routes beyond intended boundaries.",
  "likelihood_hint": "high",
  "impact_hint": "high",
  "violation_ids": ["vpc_block_public_access_not_enforced"],
  "threat_refs": [
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-284",
      "title": "Improper Access Control",
      "url": "https://cwe.mitre.org/data/definitions/284.html"
    },
    {
      "system": "https://cwe.mitre.org",
      "external_id": "CWE-668",
      "title": "Exposure of Resource to Wrong Sphere",
      "url": "https://cwe.mitre.org/data/definitions/668.html"
    }
  ],
  "remediation": {
    "title": "Enforce approved VPC Block Public Access mode",
    "description": "Configure VPC Block Public Access with an approved internet gateway block mode so public internet paths are constrained according to policy.",
    "tasks": [
      {"title": "Enable VPC Block Public Access on the VPC"},
      {"title": "Set the internet gateway block mode to one of the approved policy values"},
      {"title": "Review whether any workloads still depend on direct public ingress paths"},
      {"title": "Validate that internet-routable exposure is only present where it is explicitly intended"}
    ]
  }
}]

vpc_block_public_access := object.get(input.vpc, "BlockPublicAccessStates", {})

approved_block_public_access_mode if {
	mode := data.approved_vpc_block_public_access_modes[_]
	vpc_block_public_access.InternetGatewayBlockMode == mode
}

violation[{"id": "vpc_block_public_access_not_enforced"}] if {
	data.require_vpc_block_public_access
	not approved_block_public_access_mode
}

title := "VPC block public access should use an approved mode"
description := sprintf("VPC Block Public Access should use an approved internet gateway block mode: %s", [concat(", ", data.approved_vpc_block_public_access_modes)])
