package compliance_framework.require_flow_logs

risk_templates := [{
	"name": "VPC flow logging is not compliant",
	"title": "VPC network activity logging gap",
	"statement": "The VPC does not have approved flow log coverage with the required traffic capture, reducing the ability to detect, investigate, and audit security-relevant network activity.",
	"likelihood_hint": "medium",
	"impact_hint": "medium",
	"violation_ids": ["vpc_flow_logs_not_compliant"],
	"threat_refs": [{
		"system": "https://cwe.mitre.org",
		"external_id": "CWE-778",
		"title": "Insufficient Logging",
		"url": "https://cwe.mitre.org/data/definitions/778.html",
	}],
	"remediation": {
		"title": "Enable approved VPC flow logging",
		"description": "Configure VPC flow logs in an approved status and with the required traffic capture so network activity can be monitored and investigated.",
		"tasks": [
			{"title": "Enable VPC flow logs for the VPC"},
			{"title": "Use an approved flow log status and delivery configuration"},
			{"title": "Set traffic capture to one of the required traffic types"},
			{"title": "Confirm flow log records are reaching the expected destination for monitoring and retention"},
		],
	},
}]

approved_flow_log_status(status) if {
	approved := data.approved_flow_log_statuses[_] # regal ignore:unresolved-reference
	status == approved
}

required_traffic_type(traffic_type) if {
	required := data.required_flow_log_traffic_types[_] # regal ignore:unresolved-reference
	traffic_type == required
}

compliant_flow_log if {
	flow_log := input.vpc_context.flow_logs_for_vpc[_]
	approved_flow_log_status(flow_log.FlowLogStatus)
	required_traffic_type(flow_log.TrafficType)
}

violation[{"id": "vpc_flow_logs_not_compliant"}] if {
	data.require_vpc_flow_logs # regal ignore:unresolved-reference
	not compliant_flow_log
}

title := "VPC should have active flow logs with required traffic capture"
description := sprintf("VPC flow logs should use approved statuses: %s and capture required traffic types: %s", [concat(", ", data.approved_flow_log_statuses), concat(", ", data.required_flow_log_traffic_types)]) # regal ignore:unresolved-reference
