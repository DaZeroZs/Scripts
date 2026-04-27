Add-Type -AssemblyName System.DirectoryServices

# =========================
# CONFIG
# =========================
$ldapBaseUrl = "LDAP://ldaps.[DOMAIN]:636/c=de"

# IMPORTANT:
# Put your own user DN here.
# Example:
# $myUserDn = "cn=john.doe,ou=users,o=company,c=de"
$myUserDn = "???"

$outCsv = ".\ldap-likely-writeable-objects.csv"

$pageSize = 100

# =========================
# RIGHTS MAPPING
# =========================
# eDirectory/NDS-style commonly used bit values.
# ACL value is often: rights#scope#trustee#protectedAttribute
# The numeric rights field is the part before the first '#'.
#
# Object rights:
# 1  = Browse
# 2  = Add/Create
# 4  = Delete
# 8  = Rename
# 32 = Supervisor
#
# Attribute/property rights:
# 1  = Compare
# 2  = Read
# 4  = Write
# 8  = Add/Delete Self
# 32 = Supervisor

function Test-RightBit {
    param(
        [int]$Rights,
        [int]$Bit
    )

    return (($Rights -band $Bit) -eq $Bit)
}

function Convert-AclRights {
    param([int]$Rights)

    $names = @()

    if (Test-RightBit $Rights 1)  { $names += "Browse/Compare" }
    if (Test-RightBit $Rights 2)  { $names += "Add/Create or Read" }
    if (Test-RightBit $Rights 4)  { $names += "Delete or Write" }
    if (Test-RightBit $Rights 8)  { $names += "Rename or Self" }
    if (Test-RightBit $Rights 32) { $names += "Supervisor" }

    if ($names.Count -eq 0) {
        return "Unknown/None"
    }

    return ($names -join ", ")
}

function Test-IsLikelyWriteRight {
    param([int]$Rights)

    # Write bit or Supervisor bit
    return (
        (Test-RightBit $Rights 4) -or
        (Test-RightBit $Rights 32) -or
        (Test-RightBit $Rights 8)
    )
}

# =========================
# LDAP HELPERS
# =========================
function New-DirectoryEntry {
    param([string]$Url)

    return New-Object System.DirectoryServices.DirectoryEntry(
        $Url,
        "",
        "",
        [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    )
}

function New-LdapSearcher {
    param(
        [System.DirectoryServices.DirectoryEntry]$Entry,
        [string]$Filter,
        [string[]]$Attributes
    )

    $s = New-Object System.DirectoryServices.DirectorySearcher($Entry)
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $s.PageSize = $pageSize
    $s.Filter = $Filter
    $s.PropertiesToLoad.Clear()

    foreach ($attr in $Attributes) {
        [void]$s.PropertiesToLoad.Add($attr)
    }

    return $s
}

function Get-DnFromResult {
    param($Result)

    if ($Result.Properties.Contains("distinguishedname") -and
        $Result.Properties["distinguishedname"].Count -gt 0) {
        return [string]$Result.Properties["distinguishedname"][0]
    }

    if ($Result.Path) {
        return [string]($Result.Path -replace '^LDAP://[^/]+/', '')
    }

    return "<no DN>"
}

function Normalize-Dn {
    param([string]$Dn)

    if ([string]::IsNullOrWhiteSpace($Dn)) {
        return ""
    }

    return $Dn.Trim().ToLower()
}

function Parse-EDirAclValue {
    param([string]$AclValue)

    # Common LDAP string form:
    # rights#scope#trusteeDN#protectedAttribute
    $parts = $AclValue -split "#"

    $rights = $null
    [void][int]::TryParse($parts[0], [ref]$rights)

    $scope = if ($parts.Count -gt 1) { $parts[1] } else { "" }
    $trustee = if ($parts.Count -gt 2) { $parts[2] } else { "" }
    $protectedAttr = if ($parts.Count -gt 3) { $parts[3] } else { "" }

    [PSCustomObject]@{
        Raw              = $AclValue
        RightsNumber     = $rights
        RightsText       = if ($rights -ne $null) { Convert-AclRights $rights } else { "Unparsed" }
        Scope            = $scope
        Trustee          = $trustee
        ProtectedAttr    = $protectedAttr
        LikelyWriteRight = if ($rights -ne $null) { Test-IsLikelyWriteRight $rights } else { $false }
    }
}

# =========================
# STEP 1: Find your own trustee DNs
# =========================
$root = New-DirectoryEntry $ldapBaseUrl

Write-Host "Looking up your user and group-related trustee identities..."
Write-Host "User DN: $myUserDn"
Write-Host ""

$userEntry = New-DirectoryEntry ("LDAP://ldaps.[DOMAIN]:636/$myUserDn")

$userEntry.RefreshCache(@(
    "distinguishedName",
    "groupMembership",
    "securityEquals",
    "equivalentToMe"
))

$trustees = New-Object System.Collections.Generic.HashSet[string]

[void]$trustees.Add((Normalize-Dn $myUserDn))

foreach ($attr in @("groupMembership", "securityEquals", "equivalentToMe")) {
    if ($userEntry.Properties[$attr].Count -gt 0) {
        foreach ($v in $userEntry.Properties[$attr]) {
            [void]$trustees.Add((Normalize-Dn ([string]$v)))
        }
    }
}

Write-Host "Trustee identities used for ACL matching:"
$trustees | Sort-Object | ForEach-Object {
    Write-Host " - $_"
}
Write-Host ""

# =========================
# STEP 2: Search all objects and request ACL explicitly
# =========================
Write-Host "Searching LDAP objects and reading ACL attributes..."

$searcher = New-LdapSearcher `
    -Entry $root `
    -Filter "(objectClass=*)" `
    -Attributes @(
        "distinguishedName",
        "cn",
        "ou",
        "o",
        "objectClass",
        "description",
        "ACL"
    )

$results = $searcher.FindAll()

Write-Host "Objects found: $($results.Count)"
Write-Host ""

# =========================
# STEP 3: Parse ACLs and find likely editable objects
# =========================
$matches = New-Object System.Collections.ArrayList
$count = 0

foreach ($r in $results) {
    $count++

    $dn = Get-DnFromResult $r

    if (-not $r.Properties.Contains("acl")) {
        continue
    }

    foreach ($aclRaw in $r.Properties["acl"]) {
        $parsed = Parse-EDirAclValue ([string]$aclRaw)

        $trusteeNorm = Normalize-Dn $parsed.Trustee

        if ($trustees.Contains($trusteeNorm) -and $parsed.LikelyWriteRight) {
            $description = ""
            if ($r.Properties.Contains("description") -and $r.Properties["description"].Count -gt 0) {
                $description = @($r.Properties["description"]) -join "; "
            }

            $objectClass = ""
            if ($r.Properties.Contains("objectclass") -and $r.Properties["objectclass"].Count -gt 0) {
                $objectClass = @($r.Properties["objectclass"]) -join "; "
            }

            $row = [PSCustomObject]@{
                DN              = $dn
                Description     = $description
                ObjectClass     = $objectClass
                TrusteeMatched  = $parsed.Trustee
                RightsNumber    = $parsed.RightsNumber
                RightsText      = $parsed.RightsText
                Scope           = $parsed.Scope
                ProtectedAttr   = $parsed.ProtectedAttr
                RawAcl          = $parsed.Raw
            }

            [void]$matches.Add($row)

            Write-Host ""
            Write-Host "LIKELY EDITABLE" -ForegroundColor Green
            Write-Host "DN            : $dn"
            if ($description) {
                Write-Host "Description   : $description" -ForegroundColor Yellow
            }
            Write-Host "Trustee       : $($parsed.Trustee)"
            Write-Host "Rights        : $($parsed.RightsNumber) / $($parsed.RightsText)"
            Write-Host "ProtectedAttr : $($parsed.ProtectedAttr)"
        }
    }

    if (($count % 100) -eq 0) {
        Write-Host "Processed $count objects..."
        [GC]::Collect()
    }
}

# =========================
# STEP 4: Export
# =========================
$matches |
    Sort-Object DN, TrusteeMatched, ProtectedAttr |
    Export-Csv $outCsv -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Done."
Write-Host "Likely editable objects found: $($matches.Count)"
Write-Host "CSV exported to: $outCsv"

# =========================
# Cleanup
# =========================
$results.Dispose()
$searcher.Dispose()
$userEntry.Dispose()
$root.Dispose()
[GC]::Collect()
