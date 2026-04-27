$server = "ldaps.[DOMAIN]"
$base   = "c=de"

$authType = [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer

$entry = New-Object System.DirectoryServices.DirectoryEntry(
  "LDAP://$server`:636/$base",
  "",
  "",
  $authType
)

$criticalAttrs = @(
  "userPassword",
  "nspmPassword",
  "authPassword",
  "sasLoginSecret",
  "privateKey"
)

$metadataAttrs = @(
  "pwdFailureTime",
  "pwdAccountLockedTime",
  "passwordExpirationTime",
  "loginDisabled"
)

function Test-AnonymousAttributeExposure {
    param(
        [string]$Attribute,
        [string]$SeverityIfFound
    )

    $s = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $s.SearchScope = "Subtree"
    $s.PageSize = 500
    $s.SizeLimit = 10
    $s.Filter = "($Attribute=*)"

    $s.PropertiesToLoad.Clear()
    [void]$s.PropertiesToLoad.Add("cn")
    [void]$s.PropertiesToLoad.Add("objectClass")
    [void]$s.PropertiesToLoad.Add($Attribute)

    try {
        $results = $s.FindAll()

        [PSCustomObject]@{
            Attribute       = $Attribute
            ReturnedObjects = $results.Count
            Severity        = if ($results.Count -gt 0) { $SeverityIfFound } else { "Not exposed" }
            ValueExported   = "No"
            SamplePaths     = ($results | Select-Object -First 3 | ForEach-Object { $_.Path }) -join " | "
        }
    }
    catch {
        [PSCustomObject]@{
            Attribute       = $Attribute
            ReturnedObjects = 0
            Severity        = "Blocked/Error"
            ValueExported   = "No"
            SamplePaths     = ""
            Error           = $_.Exception.Message
        }
    }
}

$findings = @()

foreach ($attr in $criticalAttrs) {
    $findings += Test-AnonymousAttributeExposure -Attribute $attr -SeverityIfFound "CRITICAL"
}

foreach ($attr in $metadataAttrs) {
    $findings += Test-AnonymousAttributeExposure -Attribute $attr -SeverityIfFound "MEDIUM/HIGH"
}

$findings | Format-Table -AutoSize
