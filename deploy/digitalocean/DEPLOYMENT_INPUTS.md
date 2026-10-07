# DigitalOcean deployment inputs

Deployment is intentionally not active yet. Before provisioning, supply or confirm:

- DigitalOcean project and region.
- Existing VPC ID or approval to create an isolated VPC.
- SSH public-key fingerprint; never provide a private key.
- Droplet size and image preference.
- DNS name, if any. The gateway should remain private whenever possible.
- Allowed administrative source CIDRs or chosen WireGuard/Tailscale topology.
- Splunk HEC endpoint/index/sourcetype and a secret-delivery method.
- Discord webhook or application credentials through a secret-delivery method.
- Retention volume size and backup/replication requirements.
- Whether the DigitalOcean token may create/delete Droplets, VPCs, firewalls, volumes, and DNS records.

Use `DIGITALOCEAN_ACCESS_TOKEN` only in the deployment shell or secret manager. Do not put the value in `.env`, Terraform state, source files, issue text, chat transcripts, or JSONL events. Prefer a temporary scoped token and revoke it after provisioning if ongoing automation does not require it.

The first deployment remains observation/recommendation-only. Enforcement infrastructure is added only after target manifests, two enforcement targets, and action allowlists are approved.

