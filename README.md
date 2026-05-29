# AWS VPC policies

Standalone OPA/Rego policy bundle for VPC evidence emitted by the `plugin-aws-vpc` collector.

## Input schema

Each policy evaluates one VPC at a time using:

- `input.vpc`
- `input.vpc_context`

Current VPC context includes the current VPC summary, VPC attributes, DHCP options, subnets, route tables, internet gateways, VPC endpoints, flow logs, related log groups, and transit gateway attachments.

## Current coverage

This bundle currently checks VPC-level networking posture such as:

- default VPC usage
- approved VPC states
- approved IPv4 CIDR ranges
- required VPC tags
- DNS support and DNS hostnames
- approved DHCP options where configured
- VPC flow-log coverage and traffic type
- required VPC endpoints where configured
- VPC encryption settings and exclusions
- Block Public Access internet gateway mode
- network address usage metrics
- required fields in flow-log formats for encrypted VPCs

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover approved CIDRs, required tags, DNS expectations, flow-log requirements, endpoint requirements, encryption-related expectations, Block Public Access modes, and network address usage metrics.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
