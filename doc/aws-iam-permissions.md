# AI-SPM Scanner: AWS IAM Permissions Policy (Least Privilege)

This document provides the minimal, read-only AWS IAM policy required to execute the **AI-SPM Scanner**. 

The policy follows the principle of least privilege, requiring only `List`, `Describe`, and `Get` actions on AI/ML services and their dependent storage and networking components. **No write, delete, or modify permissions are required.**

---

## IAM Policy JSON (`ai-spm-readonly-policy.json`)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AISPMGeneralDiscovery",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "tag:GetResources",
        "tag:GetTagKeys"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AISPMS3ReadPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketTagging",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketPolicy",
        "s3:GetBucketPolicyStatus"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AISPMSageMakerReadPermissions",
      "Effect": "Allow",
      "Action": [
        "sagemaker:ListNotebookInstances",
        "sagemaker:DescribeNotebookInstance",
        "sagemaker:ListModels",
        "sagemaker:DescribeModel",
        "sagemaker:ListEndpointConfigs",
        "sagemaker:DescribeEndpointConfig",
        "sagemaker:ListEndpoints",
        "sagemaker:DescribeEndpoint",
        "sagemaker:ListTrainingJobs",
        "sagemaker:DescribeTrainingJob",
        "sagemaker:ListTags"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AISPMBedrockReadPermissions",
      "Effect": "Allow",
      "Action": [
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:ListFoundationModels",
        "bedrock:ListCustomModels",
        "bedrock:GetCustomModel",
        "bedrock:ListGuardrails",
        "bedrock:GetGuardrail",
        "bedrock:ListTagsForResource",
        "bedrock-agent:ListAgents",
        "bedrock-agent:GetAgent",
        "bedrock-agent:ListKnowledgeBases",
        "bedrock-agent:GetKnowledgeBase",
        "bedrock-agent:ListDataSources",
        "bedrock-agent:GetDataSource"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AISPMECRReadPermissions",
      "Effect": "Allow",
      "Action": [
        "ecr:DescribeRepositories",
        "ecr:GetRepositoryPolicy",
        "ecr:ListTagsForResource"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AISPMOpenSearchReadPermissions",
      "Effect": "Allow",
      "Action": [
        "es:ListDomainNames",
        "es:DescribeElasticsearchDomain",
        "es:DescribeElasticsearchDomainConfig",
        "es:ListTags",
        "opensearch:ListDomainNames",
        "opensearch:DescribeDomain",
        "opensearch:DescribeDomainConfig",
        "opensearch:ListTags",
        "aoss:ListCollections",
        "aoss:BatchGetCollection",
        "aoss:ListSecurityPolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AISPMKMSReadPermissions",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Deployment & Setup Guide

### Option 1: Attach via AWS CLI
```bash
# 1. Create the policy
aws iam create-policy \
  --policy-name AISPMReadOnlyPolicy \
  --policy-document file://doc/ai-spm-readonly-policy.json

# 2. Attach to your CI/CD service role or auditor user
aws iam attach-role-policy \
  --role-name AISPM-Scanner-Role \
  --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/AISPMReadOnlyPolicy
```

### Option 2: Terraform Module Snippet
```hcl
resource "aws_iam_policy" "ai_spm_readonly" {
  name        = "AISPMReadOnlyPolicy"
  description = "Minimal read-only permissions for AI-SPM Scanner"
  policy      = file("${path.module}/doc/ai-spm-readonly-policy.json")
}

resource "aws_iam_role_policy_attachment" "ai_spm_attach" {
  role       = aws_iam_role.ai_spm_scanner.name
  policy_arn = aws_iam_policy.ai_spm_readonly.arn
}
```
