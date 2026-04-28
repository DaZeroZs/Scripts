$inFile = ".\ldap-objects-full.jsonl"
$outCsv = ".\ldap-active-login-users.csv"

function Get-Attr {
    param($Obj, [string]$Name)

    if ($Obj.Attributes.PSObject.Properties.Name -contains $Name) {
        return @($Obj.Attributes.$Name)
    }

    $lowerName = $Name.ToLower()
    foreach ($p in $Obj.Attributes.PSObject.Properties) {
        if ($p.Name.ToLower() -eq $lowerName) {
            return @($p.Value)
        }
    }

    return @()
}

function Get-AttrString {
    param($Obj, [string]$Name)

    return (Get-Attr $Obj $Name) -join "; "
}

function Test-IsUserObject {
    param($Obj)

    $classes = @(Get-Attr $Obj "objectclass") | ForEach-Object {
        "$_".ToLower()
    }

    return (
        $classes -contains "user" -or
        $classes -contains "inetorgperson" -or
        $classes -contains "organizationalperson" -or
        $classes -contains "person"
    )
}

function Test-IsActiveLoginUser {
    param($Obj)

    $loginDisabled = (Get-AttrString $Obj "loginDisabled").ToLower()
    $accountDisabled = (Get-AttrString $Obj "accountDisabled").ToLower()
    $lockedByIntruder = Get-AttrString $Obj "lockedByIntruder"
    $loginExpirationTime = Get-AttrString $Obj "loginExpirationTime"

    if ($loginDisabled -in @("true", "1", "yes")) {
        return $false
    }

    if ($accountDisabled -in @("true", "1", "yes")) {
        return $false
    }

    if (-not [string]::IsNullOrWhiteSpace($lockedByIntruder)) {
        return $false
    }

    # eDirectory often uses generalized time:
    # 20260428120000Z
    if ($loginExpirationTime -match '^\d{14}Z$') {
        $expiry = [datetime]::ParseExact(
            $loginExpirationTime,
            "yyyyMMddHHmmss'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal
        )

        if ($expiry -lt (Get-Date)) {
            return $false
        }
    }

    return $true
}

$activeUsers = Get-Content $inFile | ForEach-Object {
    if ([string]::IsNullOrWhiteSpace($_)) {
        return
    }

    $obj = $_ | ConvertFrom-Json

    if ((Test-IsUserObject $obj) -and (Test-IsActiveLoginUser $obj)) {
        [PSCustomObject]@{
            DN                  = $obj.DN
            CN                  = $obj.CN
            UID                 = $obj.UID
            Mail                = $obj.Mail
            Description         = $obj.Description
            LoginDisabled       = Get-AttrString $obj "loginDisabled"
            AccountDisabled     = Get-AttrString $obj "accountDisabled"
            LockedByIntruder    = Get-AttrString $obj "lockedByIntruder"
            LoginExpirationTime = Get-AttrString $obj "loginExpirationTime"
            PasswordExpiration  = Get-AttrString $obj "passwordExpirationTime"
            ObjectClass         = Get-AttrString $obj "objectClass"
        }

    }
}

$activeUsers |
    Sort-Object DN |
    Format-Table -AutoSize -Wrap



$batchSize = 100
$allResults = @()


for ($index = 3400; $index -lt $activeUsers.Count; $index += $batchSize) {

    $batchEnd = [Math]::Min($index + $batchSize - 1, $activeUsers.Count - 1)
    $batch = $activeUsers[$index..$batchEnd]

    Write-Host "Starting batch: users $($index + 1) to $($batchEnd + 1)"
    Write-Host "----------------------------------------"

    $jobs = @()

    # ---------------------------------
    # 1. START JOBS
    # ---------------------------------
    foreach ($user in $batch) {
        $jobs += Start-Job -ArgumentList $user -ScriptBlock {
            param($u)



            function Test-LdapsLogin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserDn,

        [Parameter(Mandatory = $true)]
        [string]$Password,

        [string]$LdapHost = "ldaps.[DOMAIN]",

        [int]$LdapPort = 636
    )

    Add-Type -AssemblyName System.DirectoryServices.Protocols

    $passwordSecure = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential($UserDn, $passwordSecure)
    $plainPassword = $cred.GetNetworkCredential().Password

    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
        $LdapHost,
        $LdapPort,
        $false,
        $false
    )

    $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)

    try {
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        $conn.Credential = New-Object System.Net.NetworkCredential($UserDn, $plainPassword)

        $conn.SessionOptions.SecureSocketLayer = $true
        $conn.SessionOptions.ProtocolVersion = 3

        $conn.Bind()

        [PSCustomObject]@{
            UserDn  = $UserDn
            Success = $true
            Message = "LDAPS LOGIN SUCCESS"
        }
    }
    catch {
        [PSCustomObject]@{
            UserDn  = $UserDn
            Success = $false
            Message = $_.Exception.Message
        }
    }
    finally {
        if ($conn) {
            $conn.Dispose()
        }

        Remove-Variable plainPassword -ErrorAction SilentlyContinue
        Remove-Variable cred -ErrorAction SilentlyContinue
        Remove-Variable passwordSecure -ErrorAction SilentlyContinue

        [GC]::Collect()
    }
}


            $dn   = $u.DN

            $result = Test-LdapsLogin -UserDn $u.DN -Password "Password"

            [PSCustomObject]@{
                UID    = $dn
                Mail   = $result
                DN     = $dn
                Status = "Processed"
                Time   = Get-Date
            }
        }
    }

    # ---------------------------------
    # 2. WAIT FOR BATCH
    # ---------------------------------
    while (($jobs | Where-Object State -eq 'Running').Count -gt 0) {

        $running = ($jobs | Where-Object State -eq 'Running').Count
        $done    = ($jobs | Where-Object State -eq 'Completed').Count

        Write-Host "Running: $running | Completed: $done"

        Start-Sleep -Seconds 3
    }

    Write-Host "`nBatch finished.`n"

    # ---------------------------------
    # 3. PRINT RESULTS IMMEDIATELY
    # ---------------------------------
    $batchResults = Receive-Job -Job $jobs

    Write-Host "Results for this batch:"
    $batchResults |
        Sort-Object Mail |
        Format-Table -AutoSize

    # Save to file
    $batchResults |
    Sort-Object Mail |
    Export-Csv -Path ".\batch_results.csv" -NoTypeInformation -Append

    # Store for final summary if needed
    $allResults += $batchResults

    # ---------------------------------
    # 4. CLEANUP
    # ---------------------------------
    $jobs | Remove-Job

    Write-Host "`nMoving to next batch..."
    Write-Host "========================================`n"
}

# ---------------------------------
# FINAL SUMMARY (optional)
# ---------------------------------
Write-Host "`nAll batches completed.`n"
