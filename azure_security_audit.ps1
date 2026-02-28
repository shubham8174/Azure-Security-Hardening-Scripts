<#
.SYNOPSIS
    Azure Security Hardening & Audit Script
.DESCRIPTION
    Audits an Azure subscription against CIS Benchmark controls.
    Checks IAM, MFA, storage, network, and logging configurations.
    Author: Shubham Singh | github.com/shubhamsingh99
    Certifications: AZ-900, CCNA
.REQUIREMENTS
    Az PowerShell Module: Install-Module -Name Az -AllowClobber -Force
    Connect-AzAccount before running.
#>

param(
    [string]$SubscriptionId = "",
    [string]$OutputPath = "./azure_security_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
)

$findings = @()
$passCount = 0
$failCount = 0

function Add-Finding {
    param($Control, $Status, $Severity, $Resource, $Detail, $Recommendation)
    $findings += [PSCustomObject]@{
        Control        = $Control
        Status         = $Status
        Severity       = $Severity
        Resource       = $Resource
        Detail         = $Detail
        Recommendation = $Recommendation
    }
    if ($Status -eq "PASS") { $script:passCount++ } else { $script:failCount++ }
    $icon = if ($Status -eq "PASS") { "✅" } else { "❌" }
    Write-Host "$icon [$Severity] $Control - $Status"
}

Write-Host "`n🔐 Azure Security Hardening Audit" -ForegroundColor Cyan
Write-Host "   Author: Shubham Singh | MSc Cyber Security" -ForegroundColor Gray
Write-Host "=" * 60

# ─── SET SUBSCRIPTION ────────────────────────────────────────────
if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
}
$sub = Get-AzContext
Write-Host "`n[*] Auditing Subscription: $($sub.Subscription.Name)"

# ─── CHECK 1: MFA FOR PRIVILEGED USERS ───────────────────────────
Write-Host "`n[*] CIS 1.1 — Checking MFA for privileged accounts..."
try {
    $globalAdmins = Get-AzRoleAssignment | Where-Object { $_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "Global Administrator" }
    foreach ($admin in $globalAdmins) {
        Add-Finding `
            -Control "CIS 1.1 - MFA for Privileged Users" `
            -Status "MANUAL_CHECK" `
            -Severity "CRITICAL" `
            -Resource $admin.DisplayName `
            -Detail "Verify MFA is enforced for: $($admin.SignInName)" `
            -Recommendation "Enable MFA via Azure AD Conditional Access for all privileged roles."
    }
} catch {
    Write-Warning "Could not check admin accounts: $_"
}

# ─── CHECK 2: GUEST USERS ─────────────────────────────────────────
Write-Host "[*] CIS 1.3 — Checking for guest user accounts..."
try {
    $guestUsers = Get-AzADUser | Where-Object { $_.UserType -eq "Guest" }
    if ($guestUsers.Count -gt 0) {
        Add-Finding `
            -Control "CIS 1.3 - Guest User Restrictions" `
            -Status "WARN" `
            -Severity "MEDIUM" `
            -Resource "Azure AD" `
            -Detail "$($guestUsers.Count) guest user(s) found in directory" `
            -Recommendation "Review and remove unnecessary guest accounts. Restrict guest invitation settings."
    } else {
        Add-Finding -Control "CIS 1.3 - Guest User Restrictions" -Status "PASS" -Severity "MEDIUM" -Resource "Azure AD" -Detail "No guest users found" -Recommendation "N/A"
    }
} catch { Write-Warning "Could not check guest users: $_" }

# ─── CHECK 3: STORAGE ACCOUNT — HTTPS ONLY ────────────────────────
Write-Host "[*] CIS 3.1 — Checking storage accounts for HTTPS enforcement..."
try {
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        if (-not $sa.EnableHttpsTrafficOnly) {
            Add-Finding `
                -Control "CIS 3.1 - Secure transfer for storage" `
                -Status "FAIL" `
                -Severity "HIGH" `
                -Resource $sa.StorageAccountName `
                -Detail "HTTPS-only NOT enforced on storage account" `
                -Recommendation "Enable: Set-AzStorageAccount -Name $($sa.StorageAccountName) -ResourceGroupName $($sa.ResourceGroupName) -EnableHttpsTrafficOnly `$true"
        } else {
            Add-Finding -Control "CIS 3.1 - Secure transfer for storage" -Status "PASS" -Severity "HIGH" -Resource $sa.StorageAccountName -Detail "HTTPS enforced" -Recommendation "N/A"
        }
    }
} catch { Write-Warning "Could not check storage accounts: $_" }

# ─── CHECK 4: STORAGE PUBLIC BLOB ACCESS ──────────────────────────
Write-Host "[*] CIS 3.5 — Checking for publicly accessible blob containers..."
try {
    $storageAccounts = Get-AzStorageAccount
    foreach ($sa in $storageAccounts) {
        $ctx = $sa.Context
        $containers = Get-AzStorageContainer -Context $ctx -ErrorAction SilentlyContinue
        foreach ($container in $containers) {
            if ($container.PublicAccess -ne "Off" -and $null -ne $container.PublicAccess) {
                Add-Finding `
                    -Control "CIS 3.5 - Disable public blob access" `
                    -Status "FAIL" `
                    -Severity "HIGH" `
                    -Resource "$($sa.StorageAccountName)/$($container.Name)" `
                    -Detail "Container has PUBLIC access: $($container.PublicAccess)" `
                    -Recommendation "Disable public access on container or restrict at storage account level."
            }
        }
    }
} catch { Write-Warning "Could not check blob containers: $_" }

# ─── CHECK 5: NETWORK SECURITY GROUPS — OPEN RDP/SSH ──────────────
Write-Host "[*] CIS 6.1/6.2 — Checking NSGs for open RDP/SSH to Internet..."
try {
    $nsgs = Get-AzNetworkSecurityGroup
    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow" -and $rule.SourceAddressPrefix -in @("*", "Internet", "0.0.0.0/0")) {
                if ($rule.DestinationPortRange -in @("3389", "22") -or
                    ($rule.DestinationPortRange -eq "*")) {
                    $portName = if ($rule.DestinationPortRange -eq "3389") { "RDP" } elseif ($rule.DestinationPortRange -eq "22") { "SSH" } else { "ALL PORTS" }
                    Add-Finding `
                        -Control "CIS 6.1 - Restrict $portName from Internet" `
                        -Status "FAIL" `
                        -Severity "CRITICAL" `
                        -Resource "$($nsg.Name) — Rule: $($rule.Name)" `
                        -Detail "$portName (port $($rule.DestinationPortRange)) open to ANY source" `
                        -Recommendation "Restrict source to known IPs or use Azure Bastion/VPN for remote access."
                }
            }
        }
    }
} catch { Write-Warning "Could not check NSGs: $_" }

# ─── CHECK 6: AZURE DEFENDER / MICROSOFT DEFENDER FOR CLOUD ───────
Write-Host "[*] CIS 2.1 — Checking Microsoft Defender for Cloud status..."
try {
    $defenderPlans = Get-AzSecurityPricing
    $essentialServices = @("VirtualMachines", "SqlServers", "AppServices", "StorageAccounts")
    foreach ($svc in $essentialServices) {
        $plan = $defenderPlans | Where-Object { $_.Name -eq $svc }
        if ($plan -and $plan.PricingTier -eq "Standard") {
            Add-Finding -Control "CIS 2.1 - Defender for $svc" -Status "PASS" -Severity "HIGH" -Resource $svc -Detail "Defender for $svc enabled (Standard)" -Recommendation "N/A"
        } else {
            Add-Finding `
                -Control "CIS 2.1 - Defender for $svc" `
                -Status "FAIL" `
                -Severity "HIGH" `
                -Resource $svc `
                -Detail "Microsoft Defender NOT enabled for $svc" `
                -Recommendation "Enable in Microsoft Defender for Cloud > Environment Settings."
        }
    }
} catch { Write-Warning "Could not check Defender status: $_" }

# ─── CHECK 7: DIAGNOSTIC LOGS / ACTIVITY LOG RETENTION ────────────
Write-Host "[*] CIS 5.1 — Checking Activity Log retention (>=365 days)..."
try {
    $logProfiles = Get-AzLogProfile -ErrorAction SilentlyContinue
    if ($logProfiles) {
        foreach ($profile in $logProfiles) {
            $retentionDays = $profile.RetentionPolicy.Days
            if ($retentionDays -lt 365) {
                Add-Finding `
                    -Control "CIS 5.1 - Activity Log Retention" `
                    -Status "FAIL" `
                    -Severity "MEDIUM" `
                    -Resource $profile.Name `
                    -Detail "Log retention is only $retentionDays days (min 365 required)" `
                    -Recommendation "Set retention to 365+ days in Activity Log > Export settings."
            } else {
                Add-Finding -Control "CIS 5.1 - Activity Log Retention" -Status "PASS" -Severity "MEDIUM" -Resource $profile.Name -Detail "Retention: $retentionDays days" -Recommendation "N/A"
            }
        }
    } else {
        Add-Finding -Control "CIS 5.1 - Activity Log Retention" -Status "FAIL" -Severity "MEDIUM" -Resource "Subscription" -Detail "No log profile configured" -Recommendation "Create an Activity Log export profile with 365-day retention."
    }
} catch { Write-Warning "Could not check log profiles: $_" }

# ─── GENERATE HTML REPORT ────────────────────────────────────────────────────
Write-Host "`n[*] Generating HTML report..."

$rows = ""
foreach ($f in $findings) {
    $statusColor = switch ($f.Status) {
        "PASS"         { "background:#1a472a;color:#90EE90" }
        "FAIL"         { "background:#5c1a1a;color:#FF6B6B" }
        "WARN"         { "background:#4a3800;color:#FFD700" }
        "MANUAL_CHECK" { "background:#1a2a4a;color:#87CEEB" }
        default        { "background:#333;color:#fff" }
    }
    $sevColor = switch ($f.Severity) {
        "CRITICAL" { "color:#FF4444;font-weight:bold" }
        "HIGH"     { "color:#FF8C00" }
        "MEDIUM"   { "color:#FFD700" }
        default    { "color:#90EE90" }
    }
    $rows += "<tr>
        <td>$($f.Control)</td>
        <td style='$statusColor;padding:4px 8px;border-radius:4px;text-align:center'>$($f.Status)</td>
        <td style='$sevColor'>$($f.Severity)</td>
        <td>$($f.Resource)</td>
        <td>$($f.Detail)</td>
        <td>$($f.Recommendation)</td>
    </tr>"
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<title>Azure Security Audit - Shubham Singh</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 20px; }
  h1 { color: #58a6ff; } h2 { color: #79c0ff; }
  .summary { display:flex; gap:20px; margin:20px 0; }
  .card { padding:20px; border-radius:8px; min-width:150px; text-align:center; }
  .pass { background:#1a472a; } .fail { background:#5c1a1a; } .info { background:#1a2a4a; }
  .num { font-size:2em; font-weight:bold; }
  table { width:100%; border-collapse:collapse; margin-top:20px; }
  th { background:#161b22; padding:10px; border:1px solid #30363d; text-align:left; color:#58a6ff; }
  td { padding:8px; border:1px solid #30363d; font-size:13px; }
  tr:hover { background:#161b22; }
</style>
</head>
<body>
<h1>🔐 Azure Security Hardening Audit</h1>
<p><strong>Analyst:</strong> Shubham Singh | <strong>Date:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC | <strong>Subscription:</strong> $($sub.Subscription.Name)</p>
<div class="summary">
  <div class="card pass"><div class="num">$passCount</div>PASSED</div>
  <div class="card fail"><div class="num">$failCount</div>FAILED</div>
  <div class="card info"><div class="num">$($findings.Count)</div>TOTAL CHECKS</div>
</div>
<table>
<tr><th>Control</th><th>Status</th><th>Severity</th><th>Resource</th><th>Detail</th><th>Recommendation</th></tr>
$rows
</table>
<p style='color:#555;margin-top:30px'>Generated by Azure-Security-Hardening-Scripts | github.com/shubhamsingh99</p>
</body>
</html>
"@

$html | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "`n✅ Audit Complete!" -ForegroundColor Green
Write-Host "   PASSED: $passCount | FAILED: $failCount"
Write-Host "   Report saved: $OutputPath" -ForegroundColor Cyan
