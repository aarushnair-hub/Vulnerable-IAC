# vuln-iac-benchmark

A repo of **intentionally insecure** infrastructure-as-code, one file per
ecosystem, for benchmarking IaC/security scanners (e.g. **Checkov** vs **OX**)
side by side and seeing which catches more.

> ⚠️ **DO NOT DEPLOY ANY OF THIS.** Every file is deliberately misconfigured
> and contains fake/example credentials. It is for *scanning only*.

## Layout

| Path | Ecosystem | Checkov framework | Notes |
|------|-----------|-------------------|-------|
| `terraform/main.tf` | Terraform | `terraform` | 34 bad resources, 150+ check IDs |
| `terragrunt/vulnerable.hcl` | Terragrunt | `terraform` (rendered) | embeds bad TF via `generate` |
| `cloudformation/bad-stack.yaml` | CloudFormation | `cloudformation` | CKV_AWS_* on CFN |
| `kubernetes/bad-workloads.yaml` | Kubernetes | `kubernetes` | CKV_K8S_* |
| `helm/badchart/` | Helm | `helm` | renders insecure k8s |
| `docker/Dockerfile` | Docker | `dockerfile` | CKV_DOCKER_* |
| `pulumi/__main__.py` | Pulumi | *(none in Checkov)* | OX scans it; Checkov catches only secrets/SAST |
| `cicd/github-actions.yml` | GitHub Actions | `github_actions` | CKV_GHA_* |
| `secrets/leaked.env` | Secrets | `secrets` | CKV_SECRET_* |

### Coverage caveats
- **Pulumi**: Checkov has **no native Pulumi IaC framework**, so it will not
  flag the resource misconfigurations the way it does for Terraform. OX does
  scan Pulumi. Checkov's `secrets`/SAST scanners will still catch the hardcoded
  keys. This file is the clearest place you'll see a Checkov-vs-OX gap.
- The Terraform/Terragrunt files cover the **highest-density** resource types
  (the bulk of real findings), not every one of Checkov's 455 unique TF IDs.

## Running the scanners

```bash
# Checkov — scan the whole repo, every framework auto-detected
pip install checkov
checkov -d . --compact
# machine-readable for diffing:
checkov -d . -o json    > checkov_results.json
checkov -d . -o sarif   # checkov_results.sarif

# Per framework if you want to isolate:
checkov -d . --framework kubernetes
checkov -d . --framework dockerfile

# OX — point your OX scan / OX CLI at this repo root, export results,
# then diff the rule IDs that fired against checkov_results.json.
```

To put the CI file where the github_actions framework expects it:
```bash
mkdir -p .github/workflows && cp cicd/github-actions.yml .github/workflows/
```

## Getting the FULL policy lists (beyond AWS)

You only had AWS lists. To pull **every** Checkov policy across all clouds and
frameworks (Azure, GCP, Kubernetes, Docker, secrets, CI, …):

```bash
bash scripts/list_policies.sh
# -> ./policy_lists/all_policies.txt          (everything)
# -> ./policy_lists/checkov_AZURE.txt etc.    (per cloud)
# -> ./policy_lists/framework_kubernetes.md   (per-framework full tables)
```

Quick one-liners:
```bash
checkov --list | grep -c CKV                  # total checks
checkov --list | grep CKV_AZURE               # all Azure
checkov --list | grep CKV_GCP                 # all GCP
checkov --list | grep CKV_K8S                 # all Kubernetes
checkov --list | grep CKV_DOCKER              # all Docker
```

The authoritative, maintained per-framework tables also live in the Checkov
repo under `docs/5.Policy Index/<framework>.md` (the script fetches these).

### OX policies
OX's rule catalog is proprietary — it isn't dumped from a CLI like Checkov's.
Get it from the **OX platform → Policies/Rules** view, or the **OX API** if your
plan exposes one, then export and diff against the Checkov IDs that fired.

## How to compare
1. `checkov -d . -o json > checkov_results.json` and pull the set of failed
   check IDs.
2. Run OX on the same repo, export the set of failed rule IDs.
3. Diff the two sets per file/ecosystem to see coverage gaps. The Pulumi and
   CI files are usually where the biggest differences show up.
