package compliance_framework.require_tags

required_tag[tag] if {
  tag := data.required_vpc_tags[_]
}

missing_tag[tag] if {
  required_tag[tag]
  not tag_exists(input.vpc.Tags, tag)
}

violation[{}] if {
  count(missing_tag) > 0
}

tag_exists(tags, tag_name) if {
  some tag in tags
  lower(tag.Key) == lower(tag_name)
}

title := "VPC should set required tags"
description := sprintf("VPC tags should contain required tag keys: %s", [concat(", ", data.required_vpc_tags)])
