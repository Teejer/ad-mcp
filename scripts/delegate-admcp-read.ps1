# ============================================================================
# delegate-admcp-read.ps1
#
# Grants the AD MCP privileged service account the
# minimum permissions needed to READ every GPO in the domain, including ones
# hidden from normal accounts by per-object "Deny Read all properties" ACEs:
#
#   1. Membership in "Group Policy Creator Owners". Its inherited Full Control
#      covers every GPO object, but the inherited Allow is still weaker than a
#      per-object Deny (see step 3), so this alone may not un-hide everything.
#   2. An EXPLICIT Allow on the CN=Policies container for the account itself,
#      for "Read all properties" + LIST + open, on "all descendant objects"
#      (belt-and-suspenders: works even if group membership changes later).
#   3. Removes explicit DENY ACEs on individual GPOs that name Domain Users /
#      Authenticated Users / Everyone -- these are what actually hides GPO
#      names from the base service account. (Reported only, unless -Reconcile.)
#   4. SYSVOL read on the Policies folder (needed by get_gpo_settings for
#      Registry.pol / GptTmpl.inf parsing).
#
# Usage (on a DC, in an elevated prompt):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\delegate-admcp-read.ps1                 # preview (default = WhatIf)
#   .\delegate-admcp-read.ps1 -Apply          # make the changes
#   .\delegate-admcp-read.ps1 -Apply -RemoveDenies   # also strip deny-ACEs
#
# Notes:
#   - Explicit Deny always beats Allow in ACLs, so a Deny naming this exact
#     account can never be fixed by adding Allows; remove the deny instead
#     (-RemoveDenies handles the generic-principal denies).
#   - Re-run any time; every step is idempotent (checks before adding).
#   - -RemoveDenies does NOT touch denies naming "Server Read Only" or RODC
#     principals; those are intentional AD security.
# ============================================================================

[CmdletBinding()]
param(
    # >>> EDIT: DOMAIN\sAMAccountName of the MCP privileged service account
    #     (DOWNCASE sam: AD matches case-insensitively)
    [string]$ServiceAccount = '<EDIT-ME DOMAIN>\svc_admcp_priv',
    # >>> EDIT: \\FQDN\SYSVOL\FQDN\Policies
    [string]$SysvolPoliciesPath = '\\<EDIT-ME domain.fqdn>\SYSVOL\<domain>\Policies',
    [switch]$Apply,          # actually make changes (default: WhatIf preview)
    [switch]$RemoveDenies    # also strip deny ACEs naming Domain Users / Authenticated Users / Everyone from GPO objects
)

$WhatIf = if ($Apply) { 'Continue' } else { 'None' }
function Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "    $msg" -ForegroundColor Green }
function Warn($msg)  { Write-Host "    $msg" -ForegroundColor Yellow }

Import-Module ActiveDirectory -ErrorAction Stop
$domain  = (Get-ADDomain).DNSRoot
$baseDN  = (Get-ADDomain).DistinguishedName
$policiesContainer = "CN=Policies,CN=System,$baseDN"
$sddlOwner = '' + $baseDN   # just for reporting

# ---------------------------------------------------------------------------
Step "1/4  Group Policy Creator Owners membership for $ServiceAccount"
# ---------------------------------------------------------------------------
try {
    $acct = Get-ADUser -Identity ($ServiceAccount -replace '^.*\\','') -ErrorAction Stop
    Ok ("Account found: " + $acct.DistinguishedName)
} catch {
    Write-Error "Service account '$ServiceAccount' not found -- fix -ServiceAccount and re-run."; exit 1
}

$gpoGroup = Get-ADGroup -Identity 'Group Policy Creator Owners' -ErrorAction SilentlyContinue
if (-not $gpoGroup) {
    Warn "Group 'Group Policy Creator Owners' not found (renamed?). Skipping."
} elseif (Get-ADGroupMember -Identity 'Group Policy Creator Owners' -Recursive |
          Where-Object { $_.distinguishedName -eq $acct.DistinguishedName }) {
    Ok "Already a member of Group Policy Creator Owners."
} else {
    Add-ADGroupMember -Identity 'Group Policy Creator Owners' -Members $acct `
        -ErrorAction Stop -WhatIf:$($WhatIf -eq 'None')
    if ($Apply) { Ok "Added $($acct.SamAccountName) to Group Policy Creator Owners." }
    else        { Ok "(would add) $($acct.SamAccountName) to Group Policy Creator Owners." }
}

# ---------------------------------------------------------------------------
Step "2/4  Explicit Allow on $policiesContainer (descendant GPOs)"
# ---------------------------------------------------------------------------
$acctSid = New-Object System.Security.Principal.SecurityIdentifier($acct.SID)

# Rights needed to enumerate + read properties of every GPO object below:
#   GenericRead (0x20000000 is generic, but AD wants the discrete set below),
#   extendedRight, and Read all properties + LIST on descendants.
$rules = @(
    # Full "read all properties" on the container itself (so GPMC-style reads work)
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $acctSid,
        ([System.DirectoryServices.ActiveDirectoryRights]'ReadProperty,ReadControl,ExtendedRight,ListChildren'),
        [System.Security.AccessControl.AccessControlType]::Allow)
    # Descendants (all GPO objects): read properties + LIST + open/close
    New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $acctSid,
        ([System.DirectoryServices.ActiveDirectoryRights]'ReadProperty,ReadControl,ExtendedRight,ListChildren'),
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.Guid]::Empty,                     # all object types
        ([System.DirectoryServices.ActiveDirectorySecurityInheritance]'All'))
)

try {
    $sdi = [System.Security.Principal.IdentityReference]$acctSid
    $current = (Get-ADObject $policiesContainer -Properties nTSecurityDescriptor).nTSecurityDescriptor
    $hasRules = $current.GetAccessRules($true, $true, $sdi.GetType()) |
                Where-Object { $_.IdentityReference -eq $acctSid -and $_.AccessControlType -eq 'Allow' }
    if ($hasRules) {
        Ok "Allow ACEs for the account already present on CN=Policies ($($hasRules.Count))."
    } else {
        $secDesc = $current
        foreach ($r in $rules) { $secDesc.AddAccessRule($r) }
        if ($Apply) {
            Set-ADObject -Identity $policiesContainer -Replace @{ nTSecurityDescriptor = $secDesc }
            Ok "Added explicit Allow ACEs on CN=Policies (container + all descendants)."
        } else {
            Ok "(would add) explicit Allow ACEs on CN=Policies (container + all descendants)."
        }
    }
} catch {
    Warn "Could not update CN=Policies DACL: $($_.Exception.Message)"
    Warn "This is belt-and-suspenders only; step 1 (GPCO) may be sufficient."
}

# ---------------------------------------------------------------------------
Step "3/4  Scan GPO objects for property-read DENY ACEs (the actual hiders)"
# ---------------------------------------------------------------------------
# The service account sees GPO objects but with zero attributes -> per-object
# denies. List them so you know exactly what -RemoveDenies will change.
$denyPrincipals = @()
try {
    $domainSid = (Get-ADDomain).DomainSID
    $denyPrincipals += (New-Object System.Security.Principal.SecurityIdentifier(
        $domainSid.Value + '-513')).Value      # Domain Users
} catch { }
$denyPrincipals += @('S-1-5-11', 'S-1-1-0', $acctSid.Value)  # Auth Users, Everyone, the account itself
# Also flag any deny naming a group the account belongs to (we can't compute
# token groups from AD easily, so just list deny principals for review).
$gpos = Get-ADObject -LDAPFilter "(objectClass=groupPolicyContainer)" -SearchBase $policiesContainer -Properties nTSecurityDescriptor, displayName
$denyReport = @()
foreach ($gpo in $gpos) {
    $sd = $gpo.nTSecurityDescriptor
    if (-not $sd) { continue }
    $aces = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq 'Deny' -and ($denyPrincipals -contains $_.IdentityReference.Value) }
    if ($aces) {
        $denyReport += [pscustomobject]@{
            Name   = $gpo.displayName
            Guid   = ($gpo.Name -replace '[{}]','')
            Denies = ($aces | ForEach-Object { "$($_.IdentityReference.Value) [$($_.ActiveDirectoryRights)]" }) -join '; '
        }
    }
}
if ($denyReport.Count -eq 0) {
    Ok "No property-read deny ACEs naming generic principals found."
} else {
    $denyReport | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    if ($RemoveDenies) {
        Step "3b/4  Removing those deny ACEs"
        foreach ($gpo in $gpos) {
            $sd = $gpo.nTSecurityDescriptor
            $aces = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
                    Where-Object { $_.AccessControlType -eq 'Deny' -and ($denyPrincipals -contains $_.IdentityReference.Value) }
            if (-not $aces) { continue }
            foreach ($a in $aces) {
                if ($Apply) { $sd.RemoveAccessRuleSpecific($a) | Out-Null }
            }
            if ($Apply) {
                Set-ADObject -Identity $gpo.DistinguishedName -Replace @{ nTSecurityDescriptor = $sd }
                Ok "denies removed: $($gpo.displayName)"
            } else {
                Ok "(would remove denies) $($gpo.displayName)"
            }
        }
    } else {
        Warn "GPOs above have deny ACEs. Re-run with -Apply -RemoveDenies to strip them."
        Warn "If denies name only your service account (not generic groups), you must remove them manually -- an Allow cannot override them."
    }
}

# ---------------------------------------------------------------------------
Step "4/4  SYSVOL read access for GPO file content (Registry.pol, GptTmpl.inf)"
# ---------------------------------------------------------------------------
try {
    $acl = Get-Acl -Path $SysvolPoliciesPath -ErrorAction Stop
    $ntAccount = ($ServiceAccount -split '\\')[-1] + '@' + $domain   # UPN-ish; fallback below
    $sidRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $acctSid, 'ReadAndExecute,ReadAttributes,ReadExtendedAttributes,ReadPermissions', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $hasSysvol = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $acctSid.Value }
    if ($hasSysvol) {
        Ok "SYSVOL Policies folder already grants the account read."
    } else {
        $acl.AddAccessRule($sidRule)
        if ($Apply) {
            Set-Acl -Path $SysvolPoliciesPath -AclObject $acl
            Ok "Granted Read&Execute on $SysvolPoliciesPath (inherited)."
        } else {
            Ok "(would grant) Read&Execute on $SysvolPoliciesPath (inherited)."
        }
    }
    Ok "Note: Domain Users usually already has SYSVOL read; this rule only matters in locked-down SYSVOLs."
} catch {
    Warn "Could not read/modify ACL at $SysvolPoliciesPath : $($_.Exception.Message)"
    Warn "Use -SysvolPoliciesPath to point at the right SYSVOL policies folder."
}

# ---------------------------------------------------------------------------
Step "Done. Verification"
# ---------------------------------------------------------------------------
Write-Host @"
On the MCP host (restart the server first so it is a fresh process):
  opencode mcp disable active-directory; opencode mcp enable active-directory
then ask:  "run test_privileged and list_gpos with escalate=true"

Expected with -Apply (no -RemoveDenies):
  test_privileged.revealed_by_escalation  -> most of the 21 hidden GPO names
  still_hidden                            -> only GPOs with explicit per-object denies
Expected additionally with -RemoveDenies:
  still_hidden                            -> empty (0)

If test_privileged still shows everything hidden after a plain -Apply, the
denies are per-object: re-run with -Apply -RemoveDenies.
"@
