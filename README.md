# 🛡️ AWS S3 Bucket Misconfiguration Scanner
A Python-based tool to scan AWS S3 buckets for common security misconfigurations, including Public access via bucket policy, Public access via ACLs (Access Control Lists), Publicly exposed objects

It also generates a detailed report in **JSON and CSV formats** with **remediation suggestions**.

### 🚀 Features

- 🔍 Scans all S3 buckets in your AWS account
- 📜 Detects:
  - Public bucket policies
  - Public ACLs
  - Public object-level ACLs
- 🧠 Generates:
  - `s3_report.json`
  - `s3_report.csv`
- 💡 Provides **security fix suggestions** for each issue

### 🧰 Requirements

- Python 3.7+
- AWS credentials with permission to:
  - `s3:ListAllMyBuckets`
  - `s3:GetBucketPolicy`
  - `s3:GetBucketAcl`
  - `s3:ListBucket`
  - `s3:GetObjectAcl`

### 🔐 Setting AWS Credentials
You must set credentials before running the script.

#### For Windows, please download and install aws cli from this link:
https://awscli.amazonaws.com/AWSCLIV2.msi

#### For MAC, please download and install aws cli from this link:
https://awscli.amazonaws.com/AWSCLIV2.pkg

#### For Linux, please run this command to install aws cli:
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" unzip awscliv2.zip sudo ./aws/install

#### Use AWS CLI to set credentials
aws configure
### 🔧 Installation

#### Clone this repository
git clone https://github.com/gauravsharma-cyber/AWS-S3-Bucket-Misconfiguration-Scanne.git \
cd s3-misconfig-scanner

### Install dependencies
pip install boto3

## 🛠️ Usage

python s3_misconfig_scanner.py
\

Reports will be saved to the `output/` directory.

### 📊 Sample Output (CSV)

| Bucket        | PublicPolicy | PublicACL | ObjectsPublic | FixSuggestion |
|---------------|--------------|-----------|----------------|---------------|

### ✅ Recommended Remediations

| Issue                        | Suggestion                                                                 |
|-----------------------------|---------------------------------------------------------------------------|
| Public bucket policy        | Restrict policy to specific IAM roles/users                               |
| Public bucket ACL           | Remove `AllUsers` or `AuthenticatedUsers` grants                          |
| Public object ACLs          | Update ACL to private or bucket-owner-full-control                        |

### 🔐 Security Warning

This tool **only detects** misconfigurations. **No changes are made automatically.** Always review findings manually before making changes.

### 📄 License

MIT License. See [LICENSE](LICENSE) file.
