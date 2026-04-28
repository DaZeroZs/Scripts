Add-Type -AssemblyName System.DirectoryServices

# =========================
# Config
# =========================
$ldapUrl = "LDAP://ldaps.[DOMAIN]:636/c=de"

$outAttributes = ".\ldap-existing-attributes.txt"
$outCsv        = ".\ldap-objects-overview.csv"
$outJsonLines  = ".\ldap-objects-full.jsonl"
$outProgress   = ".\ldap-progress.txt"

$pageSize = 100

# =========================
# Cleanup old files
# =========================
Remove-Item $outAttributes, $outCsv, $outJsonLines, $outProgress -ErrorAction SilentlyContinue

# =========================
# Helper functions
# =========================
function Save-Progress {
    param([string]$Message)

    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
    Add-Content -Path $outProgress -Value $line -Encoding UTF8
    Write-Host $line
}

function New-LdapSearcher {
    param(
        [System.DirectoryServices.DirectoryEntry]$Entry,
        [string[]]$AttributesToLoad
    )

    $s = New-Object System.DirectoryServices.DirectorySearcher($Entry)
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $s.PageSize = $pageSize
    $s.Filter = "(objectClass=*)"
    $s.PropertiesToLoad.Clear()

    if ($AttributesToLoad -and $AttributesToLoad.Count -gt 0) {
        foreach ($attr in $AttributesToLoad) {
            [void]$s.PropertiesToLoad.Add($attr)
        }
    }
    else {
        [void]$s.PropertiesToLoad.Add("*")
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

function Get-PropValue {
    param(
        $Result,
        [string]$PropertyName
    )

    $key = $PropertyName.ToLower()

    if ($Result.Properties.Contains($key) -and $Result.Properties[$key].Count -gt 0) {
        return (@($Result.Properties[$key]) -join "; ")
    }

    return ""
}

function Convert-ResultToObject {
    param($Result)

    $dn = Get-DnFromResult $Result

    $attrs = [ordered]@{}

    foreach ($propName in $Result.Properties.PropertyNames | Sort-Object) {
        $attrs[$propName] = @($Result.Properties[$propName])
    }

    [PSCustomObject]@{
        DN              = $dn
        Description     = Get-PropValue $Result "description"
        Info            = Get-PropValue $Result "info"
        DisplayName     = Get-PropValue $Result "displayName"
        Comment         = Get-PropValue $Result "comment"
        ObjectClass     = Get-PropValue $Result "objectClass"
        CN              = Get-PropValue $Result "cn"
        OU              = Get-PropValue $Result "ou"
        O               = Get-PropValue $Result "o"
        C               = Get-PropValue $Result "c"
        Mail            = Get-PropValue $Result "mail"
        UID             = Get-PropValue $Result "uid"
        Member          = Get-PropValue $Result "member"
        UniqueMember    = Get-PropValue $Result "uniqueMember"
        GroupMembership = Get-PropValue $Result "groupMembership"
        SecurityEquals  = Get-PropValue $Result "securityEquals"
        EquivalentToMe  = Get-PropValue $Result "equivalentToMe"
        Owner           = Get-PropValue $Result "owner"
        Manager         = Get-PropValue $Result "manager"
        LoginDisabled   = Get-PropValue $Result "loginDisabled"
        Path            = $Result.Path

        # ALL returned attributes are stored here
        Attributes      = $attrs
    }
}

# =========================
# Start
# =========================
Save-Progress "Started LDAP export"

$entry = New-Object System.DirectoryServices.DirectoryEntry(
    $ldapUrl,
    "",
    "",
    [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
)

# =========================
# Phase 1: Discover available attributes
# =========================
Save-Progress "Phase 1: Discovering available returned attributes"

$searcher1 = New-LdapSearcher -Entry $entry -AttributesToLoad @("*")
$results1 = $searcher1.FindAll()

$attributeSet = New-Object System.Collections.Generic.HashSet[string]
$count1 = 0

foreach ($r in $results1) {
    $count1++

    foreach ($prop in $r.Properties.PropertyNames) {
        [void]$attributeSet.Add($prop.ToString())
    }

    if (($count1 % 100) -eq 0) {
        Save-Progress "Phase 1 processed $count1 objects"
    }
}

$importantAttributes = @(
    "distinguishedName",
    "cn",
    "ou",
    "o",
    "c",
    "objectClass",
    "description",
    "info",
    "displayName",
    "comment",
    "member",
    "uniqueMember",
    "groupMembership",
    "securityEquals",
    "equivalentToMe",
    "owner",
    "manager",
    "mail",
    "uid",
    "loginDisabled",
    "ACL",
    "GUID"
)

foreach ($attr in $importantAttributes) {
    [void]$attributeSet.Add($attr)
}

$attributes = @($attributeSet | Sort-Object)
$attributes | Set-Content -Path $outAttributes -Encoding UTF8

Save-Progress "Save point 1 complete: attributes saved to $outAttributes"
Save-Progress "Phase 1 objects seen: $count1"

$results1.Dispose()
$searcher1.Dispose()
[GC]::Collect()

# =========================
# Phase 2: Export objects one by one
# =========================
Save-Progress "Phase 2: Exporting objects with all returned attributes"

$searcher2 = New-LdapSearcher -Entry $entry -AttributesToLoad $attributes
$results2 = $searcher2.FindAll()

$count2 = 0
$csvInitialized = $false

foreach ($r in $results2) {
    $count2++

    $obj = Convert-ResultToObject $r

    # Direct output if description exists
    if ($obj.Description) {
        Write-Host ""
        Write-Host "DESCRIPTION: $($obj.Description)" -ForegroundColor Yellow
        Write-Host "DN         : $($obj.DN)"
    }

    # Compact CSV overview
    $csvObj = $obj | Select-Object `
        DN,
        Description,
        Info,
        DisplayName,
        Comment,
        ObjectClass,
        CN,
        OU,
        O,
        C,
        Mail,
        UID,
        Member,
        UniqueMember,
        GroupMembership,
        SecurityEquals,
        EquivalentToMe,
        Owner,
        Manager,
        LoginDisabled,
        Path

    if (-not $csvInitialized) {
        $csvObj | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8
        $csvInitialized = $true
    }
    else {
        $csvObj | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8 -Append
    }

    # Full export: one complete LDAP object per line
    # This includes ALL returned attributes in .Attributes
    $obj |
        ConvertTo-Json -Depth 50 -Compress |
        Add-Content -Path $outJsonLines -Encoding UTF8

    if (($count2 % 50) -eq 0) {
        Save-Progress "Phase 2 exported $count2 objects"
        [GC]::Collect()
    }
}

Save-Progress "Save point 2 complete: exported $count2 objects"
Save-Progress "Attribute list saved to : $outAttributes"
Save-Progress "CSV overview saved to   : $outCsv"
Save-Progress "Full JSONL saved to     : $outJsonLines"

# =========================
# Cleanup
# =========================
$results2.Dispose()
$searcher2.Dispose()
$entry.Dispose()
[GC]::Collect()

Save-Progress "Finished LDAP export"
