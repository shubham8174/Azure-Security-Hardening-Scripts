# ☁️ Azure Security Hardening Scripts

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Azure](https://img.shields.io/badge/Azure-Security-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![CIS Benchmark](https://img.shields.io/badge/CIS-Benchmark-red?style=for-the-badge)

> PowerShell-based Azure security audit tool that checks subscriptions against CIS Microsoft Azure Foundations Benchmark controls — generating a professional HTML report with findings and remediation guidance.

---

## 📌 Overview

Misconfigured cloud environments are responsible for a significant portion of enterprise breaches. This script audits Azure subscriptions across 7 critical CIS Benchmark control categories — IAM, MFA, storage security, network security groups, Microsoft Defender, and logging — and outputs a color-coded HTML report with actionable remediation steps.

Built with hands-on Azure security experience and aligned to the **SC-200** and **AZ-500** certification domains.

---

## ✨ CIS Controls Covered

| Control | Category | Severity |
|---|---|---|
| CIS 1.1 | MFA for privileged accounts | CRITICAL |
| CIS 1.3 | Guest user restrictions | MEDIUM |
| CIS 3.1 | HTTPS-only storage accounts | HIGH |
| CIS 3.5 | Disable public blob access | HIGH |
| CIS 6.1 | Restrict RDP from Internet | CRITICAL |
| CIS 6.2 | Restrict SSH from Internet | CRITICAL |
| CIS 2.1 | Microsoft Defender for Cloud | HIGH |
| CIS 5.1 | Activity log retention 365 days | MEDIUM |

---

## 🛠️ Prerequisites

```powershell
# Install Az PowerShell module
Install-Module -Name Az -AllowClobber -Force

# Connect to Azure
Connect-AzAccount
```

---

## 🚀 Usage

```powershell
# Audit current subscription (opens HTML report)
.\azure_security_audit.ps1

# Audit specific subscription
.\azure_security_audit.ps1 -SubscriptionId "your-subscription-id"

# Custom output path
.\azure_security_audit.ps1 -OutputPath "C:\Reports\azure_audit.html"
```

---

## 📊 Sample Report Output

```
🔐 Azure Security Hardening Audit
   Author: Shubham Singh | MSc Cyber Security
============================================================

✅ [HIGH]     CIS 3.1 - Secure transfer         PASS  storageaccount01
❌ [CRITICAL] CIS 6.1 - Restrict RDP            FAIL  nsg-prod — Rule: allow-rdp
❌ [HIGH]     CIS 2.1 - Defender for VMs        FAIL  VirtualMachines
✅ [MEDIUM]   CIS 1.3 - Guest Users             PASS  Azure AD
❌ [HIGH]     CIS 3.5 - Public Blob Access      FAIL  storageaccount01/public-data
✅ [HIGH]     CIS 3.1 - HTTPS Storage           PASS  storageaccount02

✅ Audit Complete!
   PASSED: 8 | FAILED: 5
   Report saved: azure_security_audit_20240615_143022.html
```

The HTML report is **dark-themed**, color-coded by severity, and includes remediation PowerShell commands for each failed control.

---

## 📁 Project Structure

```
Azure-Security-Hardening-Scripts/
│
├── azure_security_audit.ps1     # Main audit script
├── remediation/                 # Individual remediation scripts
│   ├── fix_storage_https.ps1
│   ├── fix_nsg_rdp.ps1
│   └── enable_defender.ps1
└── README.md
```

---

## 🔮 Roadmap

- [ ] Additional CIS controls (1.x IAM full coverage)
- [ ] Azure Policy compliance integration
- [ ] Multi-subscription tenant-wide audit
- [ ] CSV export for compliance reporting
- [ ] Scheduled audit via Azure Automation Runbook

---

## 🎯 Relevant Certifications

This project covers domains tested in:
- **SC-200** — Microsoft Security Operations Analyst
- **AZ-500** — Microsoft Azure Security Engineer
- **CIS Azure Foundations Benchmark v2.0**

---

## 👤 Author

**Shubham Singh**
MSc Cyber Security — University of Southampton 🇬🇧
Information Security Analyst | Azure Security | AZ-900 Certified

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/shubham-singh99/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/shubham8174)


