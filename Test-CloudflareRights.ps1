<#
================================================================================
HOW TO USE
================================================================================

1. ENVIRONMENT VARIABLE SETZEN
--------------------------------

$env:CLOUDFLARE_API_TOKEN = "your-cloudflare-api-token"

2. SCRIPT LADEN
--------------------------------

. .\Test-CloudflareRights.ps1

3. STANDARD AUDIT AUSFÜHREN
--------------------------------

$result = Test-CloudflareRights

4. OUTPUT DATEIEN
--------------------------------

.\cloudflare-audit-output\global-checks.csv
.\cloudflare-audit-output\accounts.csv
.\cloudflare-audit-output\zones.csv
.\cloudflare-audit-output\zone-rights-matrix.csv
.\cloudflare-audit-output\summary.json

================================================================================
#>

function Test-CloudflareRights {
    param(
        [string]$ApiToken = $env:CLOUDFLARE_API_TOKEN,
        [string]$OutputDir = ".\cloudflare-audit-output"
    )

    function Invoke-CloudflareApi {
        param(
            [string]$Method = "GET",
            [string]$Path,
            [object]$Body = $null
        )

        $uri = "https://api.cloudflare.com/client/v4/$($Path.TrimStart('/'))"

        try {
            if ($null -ne $Body) {
                Invoke-RestMethod `
                    -Method $Method `
                    -Uri $uri `
                    -Headers $script:Headers `
                    -Body ($Body | ConvertTo-Json -Depth 10) `
                    -ContentType "application/json" `
                    -ErrorAction Stop
            }
            else {
                Invoke-RestMethod `
                    -Method $Method `
                    -Uri $uri `
                    -Headers $script:Headers `
                    -ErrorAction Stop
            }
        }
        catch {
            [PSCustomObject]@{
                Error      = $true
                Method     = $Method
                Uri        = $uri
                StatusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { $null }
                Message    = $_.Exception.Message
            }
        }
    }

    function Test-CloudflareEndpoint {
        param(
            [string]$Name,
            [string]$Method,
            [string]$Path,
            [string]$Meaning
        )

        $result = Invoke-CloudflareApi -Method $Method -Path $Path

        [PSCustomObject]@{
            Check      = $Name
            Method     = $Method
            Endpoint   = $Path
            Status     = if ($result.Error -or $result.success -eq $false) { "Denied/Error" } else { "OK" }
            StatusCode = if ($result.Error) { $result.StatusCode } else { 200 }
            Meaning    = $Meaning
        }
    }

    if (-not $ApiToken) {
        throw "CLOUDFLARE_API_TOKEN ist leer."
    }

    $script:Headers = @{
        Authorization = "Bearer $ApiToken"
        "Content-Type" = "application/json"
    }

    Write-Host "`n=== Cloudflare Permission Audit ===" -ForegroundColor Cyan

    Write-Host "`n[1] Token Verification" -ForegroundColor Cyan

    # Cloudflare offizieller Token-Verify Endpoint:
    # GET /user/tokens/verify
    $tokenVerify = Invoke-CloudflareApi -Path "user/tokens/verify"

    if ($tokenVerify.Error -or $tokenVerify.success -eq $false) {
        Write-Host "[-] Token konnte nicht verifiziert werden." -ForegroundColor Red
        $tokenVerify | Format-List
        return
    }

    $tokenVerify.result | Format-List

    Write-Host "`n[2] Global Permission Indicators" -ForegroundColor Cyan

    $globalChecks = @(
        Test-CloudflareEndpoint "Verify token"              "GET" "user/tokens/verify"       "Token ist gültig"
        Test-CloudflareEndpoint "Read user details"         "GET" "user"                     "User-Profil lesbar"
        Test-CloudflareEndpoint "List accounts"             "GET" "accounts"                 "Accounts sichtbar"
        Test-CloudflareEndpoint "List zones"                "GET" "zones"                    "Zonen sichtbar"
        Test-CloudflareEndpoint "List memberships"          "GET" "memberships"              "Account-Mitgliedschaften sichtbar"
        Test-CloudflareEndpoint "List user tokens"          "GET" "user/tokens"              "Token-Verwaltung sichtbar"
    )

    $globalChecks | Format-Table -AutoSize

    Write-Host "`n[3] Accounts" -ForegroundColor Cyan

    $accountsResponse = Invoke-CloudflareApi -Path "accounts"
    $accounts = @()

    if (-not $accountsResponse.Error -and $accountsResponse.success -ne $false) {
        $accounts = @($accountsResponse.result)

        $accounts |
            Select-Object id, name, type |
            Format-Table -AutoSize
    }
    else {
        Write-Host "[-] Accounts konnten nicht gelesen werden." -ForegroundColor Yellow
    }

    Write-Host "`n[4] Zones" -ForegroundColor Cyan

    $zonesResponse = Invoke-CloudflareApi -Path "zones"
    $zones = @()

    if (-not $zonesResponse.Error -and $zonesResponse.success -ne $false) {
        $zones = @($zonesResponse.result)

        $zones |
            Select-Object id, name, status, paused, type |
            Format-Table -AutoSize
    }
    else {
        Write-Host "[-] Zones konnten nicht gelesen werden." -ForegroundColor Yellow
    }

    Write-Host "`n[5] Account Rights Matrix" -ForegroundColor Cyan

    $accountMatrix = @()

    foreach ($account in $accounts) {
        $accountId = $account.id

        $checks = @(
            @{
                Name = "Read account"
                Path = "accounts/$accountId"
                Meaning = "Account-Details lesbar"
            },
            @{
                Name = "List account members"
                Path = "accounts/$accountId/members"
                Meaning = "Mitglieder lesbar / Account-Admin-Indikator"
            },
            @{
                Name = "List account roles"
                Path = "accounts/$accountId/roles"
                Meaning = "Rollen lesbar"
            },
            @{
                Name = "List account tokens"
                Path = "accounts/$accountId/tokens"
                Meaning = "Account Token-Verwaltung sichtbar"
            },
            @{
                Name = "List workers scripts"
                Path = "accounts/$accountId/workers/scripts"
                Meaning = "Workers lesbar"
            },
            @{
                Name = "List pages projects"
                Path = "accounts/$accountId/pages/projects"
                Meaning = "Pages Projekte lesbar"
            },
            @{
                Name = "List R2 buckets"
                Path = "accounts/$accountId/r2/buckets"
                Meaning = "R2 Buckets lesbar"
            }
        )

        foreach ($check in $checks) {
            $r = Invoke-CloudflareApi -Path $check.Path

            $accountMatrix += [PSCustomObject]@{
                AccountName = $account.name
                AccountId   = $accountId
                Check       = $check.Name
                Endpoint    = $check.Path
                Access      = if ($r.Error -or $r.success -eq $false) { "NO" } else { "YES" }
                StatusCode  = if ($r.Error) { $r.StatusCode } else { 200 }
                Meaning     = $check.Meaning
            }
        }
    }

    $accountMatrix |
        Sort-Object AccountName, Check |
        Format-Table -AutoSize

    Write-Host "`n[6] Zone Rights Matrix" -ForegroundColor Cyan

    $zoneMatrix = @()

    foreach ($zone in $zones) {
        $zoneId = $zone.id

        $checks = @(
            @{
                Name = "Read zone"
                Path = "zones/$zoneId"
                Meaning = "Zone-Details lesbar"
            },
            @{
                Name = "Read DNS records"
                Path = "zones/$zoneId/dns_records"
                Meaning = "DNS Records lesbar"
            },
            @{
                Name = "Read firewall rules"
                Path = "zones/$zoneId/firewall/rules"
                Meaning = "Firewall Rules lesbar"
            },
            @{
                Name = "Read page rules"
                Path = "zones/$zoneId/pagerules"
                Meaning = "Page Rules lesbar"
            },
            @{
                Name = "Read cache settings"
                Path = "zones/$zoneId/settings/cache_level"
                Meaning = "Zone Settings lesbar"
            },
            @{
                Name = "Read SSL settings"
                Path = "zones/$zoneId/settings/ssl"
                Meaning = "SSL Settings lesbar"
            },
            @{
                Name = "Read WAF packages"
                Path = "zones/$zoneId/firewall/waf/packages"
                Meaning = "WAF lesbar"
            },
            @{
                Name = "Read analytics dashboard"
                Path = "zones/$zoneId/analytics/dashboard"
                Meaning = "Analytics lesbar"
            }
        )

        foreach ($check in $checks) {
            $r = Invoke-CloudflareApi -Path $check.Path

            $zoneMatrix += [PSCustomObject]@{
                ZoneName   = $zone.name
                ZoneId     = $zoneId
                Check      = $check.Name
                Endpoint   = $check.Path
                Access     = if ($r.Error -or $r.success -eq $false) { "NO" } else { "YES" }
                StatusCode = if ($r.Error) { $r.StatusCode } else { 200 }
                Meaning    = $check.Meaning
            }
        }
    }

    $zoneMatrix |
        Sort-Object ZoneName, Check |
        Format-Table -AutoSize

    Write-Host "`n[7] Summary" -ForegroundColor Cyan

    $summary = [PSCustomObject]@{
        TokenValid             = $true
        TokenId                = $tokenVerify.result.id
        TokenStatus            = $tokenVerify.result.status
        GlobalCanReadUser      = (($globalChecks | Where-Object Check -eq "Read user details").Status -eq "OK")
        GlobalCanListAccounts  = (($globalChecks | Where-Object Check -eq "List accounts").Status -eq "OK")
        GlobalCanListZones     = (($globalChecks | Where-Object Check -eq "List zones").Status -eq "OK")
        GlobalCanListTokens    = (($globalChecks | Where-Object Check -eq "List user tokens").Status -eq "OK")
        AccountCount           = @($accounts).Count
        ZoneCount              = @($zones).Count
        AccountYesChecks       = @($accountMatrix | Where-Object Access -eq "YES").Count
        ZoneYesChecks          = @($zoneMatrix | Where-Object Access -eq "YES").Count
    }

    $summary | Format-List

    Write-Host "`n[8] Export" -ForegroundColor Cyan

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $globalChecks  | Export-Csv "$OutputDir\global-checks.csv" -NoTypeInformation -Encoding UTF8
    $accounts      | Select-Object id, name, type | Export-Csv "$OutputDir\accounts.csv" -NoTypeInformation -Encoding UTF8
    $zones         | Select-Object id, name, status, paused, type | Export-Csv "$OutputDir\zones.csv" -NoTypeInformation -Encoding UTF8
    $accountMatrix | Export-Csv "$OutputDir\account-rights-matrix.csv" -NoTypeInformation -Encoding UTF8
    $zoneMatrix    | Export-Csv "$OutputDir\zone-rights-matrix.csv" -NoTypeInformation -Encoding UTF8
    $summary       | ConvertTo-Json -Depth 10 | Out-File "$OutputDir\summary.json" -Encoding UTF8

    Write-Host "`n[+] Fertig." -ForegroundColor Green
    Write-Host "[+] Output:"
    Write-Host "    $OutputDir\global-checks.csv"
    Write-Host "    $OutputDir\accounts.csv"
    Write-Host "    $OutputDir\zones.csv"
    Write-Host "    $OutputDir\account-rights-matrix.csv"
    Write-Host "    $OutputDir\zone-rights-matrix.csv"
    Write-Host "    $OutputDir\summary.json"

    return [PSCustomObject]@{
        TokenVerify   = $tokenVerify
        GlobalChecks  = $globalChecks
        Accounts      = $accounts
        Zones         = $zones
        AccountMatrix = $accountMatrix
        ZoneMatrix    = $zoneMatrix
        Summary       = $summary
        OutputDir     = $OutputDir
    }
}
