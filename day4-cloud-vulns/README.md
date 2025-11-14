# Day 4: Cloud Vulns (AWS) - Misconfigs & IAM Abuse Sim

## Goal
Simulate AWS cloud vulnerabilities: S3 public ACLs, over-privileged IAM, open security groups.

## Terraform Deploy
- Ran `terraform plan` and `apply` to create misconfigured resources.

## Exploitation
- S3 Leak: Anonymous access to public bucket.
- IAM Abuse: Assume admin role via weakuser, create backdoor.
- EC2 Pivot: SSH into open instance for lateral movement.

## Mindset
Cloud breaches expose weak ACLs—evade by conditional policies.

## Win Check
Scripts run successfully in sim. Chain: Recon -> Abuse -> Pivot.
