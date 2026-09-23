# ============================================================================
# delegate-admcp-gpo-read.ps1
#
# Read-only ADDITIVE delegation for the AD MCP GPO tools, via a group.
#
# EDIT THESE THREE for your environment (or pass them as parameters):
#   $ReaderGroup     = DN of the group the read ACEs are granted to
#   $MemberAccount   = sAMAccountName of the MCP escalation service account
#   $SysvolPoliciesPath = \\<<domain>>\SYSVOL\<<domain>>\Policies
#
# This script only ever ADDS things:
#   * membership of $MemberAccount in $ReaderGroup (if not already present)
#   * on every GPO under CN=Policies, an Allow ACE for the group:
#         ReadProperty, ReadControl, ExtendedRight, ListChildren
#     (no WriteProperty/WriteDAC/WriteOwner/Delete/child-create -- read only)
#   * (-IncludeSysvol only) inherited Read&Execute on the SYSVOL Policies
#     folder for GPO file content
#
# It NEVER removes, edits, or reorders any existing ACE, and it never removes
# group members. If GPOs stay hidden after running it, the cause is explicit
# DENY ACEs (Deny always beats Allow) -- the script only REPORTS those so they
# can be handled deliberately elsewhere.
#
# Usage (elevated, on a DC or RSAT box):
#   Set-ExecutionPolicy -Scope Process Bypass -Force
#   .\delegate-admcp-gpo-read.ps1              # preview (default, changes nothing)
#   .\delegate-admcp-gpo-read.ps1 -Apply       # make the additions
#   .\delegate-admcp-gpo-read.ps1 -Apply -IncludeSysvol   # + SYSVOL read
#
# Re-run any time after new GPOs are created: it enumerates every GPO, skips
# those that already carry the group's read ACE, and grants only the new ones.
#
# To revoke: remove the group membership in ADUC (ACEs on GPOs become inert
# once no member of the group exists; delete the group later if you want the
# ACE objects cleaned from ACLs, or use ADSI Edit per object).
# ============================================================================

[CmdletBinding()]
param(
    # Group the read ACEs are granted to (accepts DN, name, or sAMAccountName).
    # >>> EDIT: DN of YOUR reader group, e.g.
    #     'CN=GPO MCP Readers,OU=Groups,DC=corp,DC=example,DC=com'
    [string]$ReaderGroup = 'CN=<EDIT-ME GPO MCP Readers>,DC=<domain>,DC=<com>',

    # Ensure the MCP escalation account is a member of that group.
    # >>> EDIT: the service account that AD_PRIV_DN points at.
    [string]$MemberAccount = '<EDIT-ME svc_admcp_priv>',

    # Only used with -IncludeSysvol.
    # >>> EDIT: \\FQDN\SYSVOL\FQDN\Policies
    [string]$SysvolPoliciesPath = '\\<EDIT-ME domain.fqdn>\SYSVOL\<domain>\Policies',

    # Catches mistyped flags (e.g. --apply): they land here because no other
    # positional parameter is defined, and we error out instead of silently
    # binding them to -ReaderGroup.
    [Parameter(Position = 999)]
    $Leftovers = $null,

    # Optional: also grant the group inherited Read&Execute on the SYSVOL
    # Policies folder (GPO file content: Registry.pol / GptTmpl.inf). Off by
    # default -- Domain Users already has SYSVOL read in default configs.
    [switch]$IncludeSysvol,

    [switch]$Apply
)

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    $m" -ForegroundColor Green }
function Warn($m) { Write-Host "    $m" -ForegroundColor Yellow }

# Guard the classic cmd-style-flag trap: PowerShell binds '--apply' as a
# positional value (silently!) instead of erroring; with -Leftovers it is
# caught here and reported as a mistake.
if ($Leftovers) {
    Write-Error ("Unexpected argument(s): " + (@($Leftovers) -join ', ') + " -- PowerShell switches are single-dash: use -Apply (not --apply).")
    exit 2
}

Import-Module ActiveDirectory -ErrorAction Stop
$baseDN   = (Get-ADDomain).DistinguishedName
$policies = "CN=Policies,CN=System,$baseDN"

# ---------------------------------------------------------------------------
Step "Reader group: $ReaderGroup"
# ---------------------------------------------------------------------------
# DN / name / sAMAccountName all work with -Identity.
$grp = Get-ADGroup -Identity $ReaderGroup -ErrorAction Stop
$sid = New-Object System.Security.Principal.SecurityIdentifier($grp.SID)
Ok "Group: $($grp.DistinguishedName)"
Ok "SID  : $($sid.Value)"

$acct = $null
if ($MemberAccount) {
    $acct = Get-ADUser -Identity $MemberAccount -ErrorAction Stop
    Ok "Member account: $($acct.DistinguishedName)"

    if (Get-ADGroupMember -Identity $grp.DistinguishedName -ErrorAction SilentlyContinue |
        Where-Object { $_.distinguishedName -eq $acct.DistinguishedName }) {
        Ok "$($acct.SamAccountName) is already a member."
    } elseif ($Apply) {
        Add-ADGroupMember -Identity $grp.DistinguishedName -Members $acct
        Ok "Added $($acct.SamAccountName) to $($grp.Name)."
    } else {
        Ok "(would add) $($acct.SamAccountName) to $($grp.Name)."
    }
}

# ---------------------------------------------------------------------------
Step "GPO objects: enumerate ALL GPOs and grant read to the group"
# ---------------------------------------------------------------------------
# Rights granted. Explicitly NOT granted: WriteProperty, WriteDAC, WriteOwner,
# Delete, Create/Delete children, GenericAll/GenericWrite.
$READ_RIGHTS = [System.DirectoryServices.ActiveDirectoryRights]'ReadProperty, ReadControl, ExtendedRight, ListChildren'

$gpoObjs = @(Get-ADObject -LDAPFilter "(objectClass=groupPolicyContainer)" `
                           -SearchBase $policies `
                           -Properties nTSecurityDescriptor, displayName)
Ok "$($gpoObjs.Count) GPO objects enumerated under $policies"
if ($gpoObjs.Count -eq 0) {
    Warn "Zero GPOs found -- wrong domain, or the account cannot list the container. Nothing else to do."
    exit 1
}

function Test-ReadGranted($sd, $sidObj) {
    if (-not $sd) { return $false }
    # IMPORTANT: check the RAW ACE list (first $true = includeNotInheritedOnly).
    # GetAccessRules($false/$true, ...) also returns *inherited/effective* ACEs,
    # which makes us think a GPO is already covered when the allow actually
    # comes from an ancestor object and was never written on this GPO itself.
    $r = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
         Where-Object { -not $_.IsInherited -and
                        $_.IdentityReference.Value -eq $sidObj.Value -and
                        $_.AccessControlType -eq 'Allow' -and
                        $_.ActiveDirectoryRights -match 'ReadProperty' }
    return [bool]$r
}

$already = 0; $added = 0; $unreadable = 0; $failed = 0
$denyReport = @()
foreach ($gpo in $gpoObjs) {
    $sd = $gpo.nTSecurityDescriptor
    if (-not $sd) { $unreadable++; Warn ("DACL unreadable: " + $gpo.displayName); continue }

    # Report-only: list any DENY ACEs on this GPO naming generic principals,
    # so you can decide separately whether they should be changed. The script
    # does not touch them.
    $denies = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) |
              Where-Object { $_.AccessControlType -eq 'Deny' }
    foreach ($d in $denies) {
        $denyReport += "$($gpo.displayName) : $($d.IdentityReference.Value) [$($d.ActiveDirectoryRights)]"
    }

    if (Test-ReadGranted $sd $sid) { $already++; continue }

    # Grant on THIS GPO only (leaf object -- no inheritance flags).
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid, $READ_RIGHTS,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.Guid]::Empty,
        ([System.DirectoryServices.ActiveDirectorySecurityInheritance]::None))
    $sd.AddAccessRule($rule)
    try {
        if ($Apply) {
            Set-ADObject -Identity $gpo.DistinguishedName -Replace @{nTSecurityDescriptor = $sd}
        }
        $added++
    } catch {
        $failed++
        Warn ("Set-ADObject failed on " + $gpo.displayName + ": " + $_.Exception.Message)
    }
}
$verb = if ($Apply) { "granted" } else { "would grant" }
Ok "Read ACEs: $verb on $added GPOs; $already already had it; $unreadable unreadable; $failed failed"

if ($denyReport.Count -gt 0) {
    Warn "NOTE: $($denyReport.Count) DENY ACEs exist on GPOs (listed below). An"
    Warn "Allow cannot override a Deny: GPOs denied to principals your service"
    Warn "account belongs to may stay hidden even after this delegation."
    Warn "This script does NOT remove any of them."
    $denyReport | Sort-Object | Get-Unique | ForEach-Object { Write-Host "      $_" -ForegroundColor Yellow }
} else {
    Ok "No DENY ACEs found on any GPO."
}

# ---------------------------------------------------------------------------
if ($IncludeSysvol) {
    Step "SYSVOL Policies folder read for the group"
    try {
        $acl = Get-Acl -Path $SysvolPoliciesPath
        $hasSysvol = $acl.Access | Where-Object { $_.IdentityReference.Value -eq $sid.Value }
        if ($hasSysvol) {
            Ok "Already granted on $SysvolPoliciesPath."
        } else {
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid, 'ReadAndExecute,ReadAttributes,ReadExtendedAttributes,ReadPermissions',
                'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
            if ($Apply) {
                Set-Acl -Path $SysvolPoliciesPath -AclObject $acl
                Ok "Granted Read&Execute (inherited) on $SysvolPoliciesPath."
            } else {
                Ok "(would grant) Read&Execute (inherited) on $SysvolPoliciesPath."
            }
        }
    } catch {
        Warn "SYSVOL ACL not writable from here: $($_.Exception.Message)"
        Warn "Usually unnecessary: Domain Users already has SYSVOL read in default configs."
    }
} else {
    Step "SYSVOL Policies folder: skipped (pass -IncludeSysvol to grant read)"
    Ok "Skipped. GPO file content (Registry.pol / GptTmpl.inf) relies on the"
    Ok "existing SYSVOL permissions, which Domain Users normally already has."
}

# ---------------------------------------------------------------------------
Write-Host @"

Done. Summary:
  - readers group : $($grp.DistinguishedName) (member: $($acct.SamAccountName))
  - GPO reads     : per-GPO Allow ACEs (ReadProperty + ReadControl +
                    ExtendedRight + ListChildren). Read-only; no deny or
                    existing ACE was touched.
  - New GPOs do NOT inherit the ACE automatically in this mode: re-run this
    script after creating GPOs -- it skips GPOs that already have the ACE.
  - To revoke: remove the group membership (the ACEs do nothing without
    members).

Verify from the MCP host after 'opencode mcp disable/enable active-directory':
  test_privileged      -> revealed_by_escalation should list previously hidden GPOs
  list_gpos -escalate  -> 'acl_hidden' entries gone (unless a deny still wins)
"@
