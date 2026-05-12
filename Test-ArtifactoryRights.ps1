<#
================================================================================
HOW TO USE
================================================================================

1. ENVIRONMENT VARIABLES SETZEN
--------------------------------

$env:ARTIFACTORY_REPOSITORY = "https://artifactory.example.com/artifactory"
$env:ARTIFACTORY_USERNAME   = "myuser"
$env:ARTIFACTORY_PASSWORD   = "mypassword"

2. SCRIPT LADEN
--------------------------------

. .\Test-ArtifactoryRights.ps1

(Der Punkt + Leerzeichen davor ist wichtig)

3. STANDARD AUDIT AUSFÜHREN
--------------------------------

$result = Test-ArtifactoryRights

4. MIT DEPLOY/DELETE TEST
--------------------------------

$result = Test-ArtifactoryRights -TestDeploy

ACHTUNG:
- Lädt kleine Testdateien hoch
- Versucht diese anschließend wieder zu löschen
- Nur in autorisierten Umgebungen verwenden

5. OUTPUT DATEIEN
--------------------------------

.\artifactory-audit-output\repo-rights-matrix.csv
.\artifactory-audit-output\global-checks.csv
.\artifactory-audit-output\summary.json

6. CUSTOM PARAMETER
--------------------------------

$result = Test-ArtifactoryRights `
    -ArtifactoryUrl "https://target/artifactory" `
    -Username "user" `
    -Password "pass"

================================================================================
#>

function Test-ArtifactoryRights {
    param(
        [string]$ArtifactoryUrl = $env:ARTIFACTORY_REPOSITORY,
        [string]$Username       = $env:ARTIFACTORY_USERNAME,
        [string]$Password       = $env:ARTIFACTORY_PASSWORD,
        [switch]$TestDeploy,
        [string]$OutputDir      = ".\artifactory-audit-output"
    )

    function Normalize-ArtifactoryUrl {
        param([string]$Url)

        if (-not $Url) {
            throw "ARTIFACTORY_REPOSITORY / ArtifactoryUrl ist leer."
        }

        $Url = $Url.TrimEnd("/")

        if ($Url -match "^(https?://[^/]+)(/artifactory)?") {
            return "$($matches[1])/artifactory"
        }

        return $Url
    }

    function Invoke-ArtifactoryApi {
        param(
            [string]$Method = "GET",
            [string]$Path,
            [hashtable]$Headers,
            [object]$Body = $null,
            [string]$ContentType = "application/json"
        )

        $uri = "$script:BaseUrl/$($Path.TrimStart('/'))"

        try {
            if ($null -ne $Body) {
                Invoke-RestMethod `
                    -Method $Method `
                    -Uri $uri `
                    -Headers $Headers `
                    -Body $Body `
                    -ContentType $ContentType `
                    -ErrorAction Stop
            }
            else {
                Invoke-RestMethod `
                    -Method $Method `
                    -Uri $uri `
                    -Headers $Headers `
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

    function Test-ArtifactoryEndpoint {
        param(
            [string]$Name,
            [string]$Method,
            [string]$Path,
            [string]$Meaning
        )

        $result = Invoke-ArtifactoryApi `
            -Method $Method `
            -Path $Path `
            -Headers $script:Headers

        [PSCustomObject]@{
            Check      = $Name
            Method     = $Method
            Endpoint   = $Path
            Status     = if ($result.Error) { "Denied/Error" } else { "OK" }
            StatusCode = if ($result.Error) { $result.StatusCode } else { 200 }
            Meaning    = $Meaning
        }
    }

    if (-not $Password) {
        throw "ARTIFACTORY_PASSWORD / Password ist leer."
    }

    $script:BaseUrl = Normalize-ArtifactoryUrl $ArtifactoryUrl

    if ($Username) {
        $pair = "$($Username):$($Password)"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))

        $script:Headers = @{
            Authorization = "Basic $encoded"
        }

        $authMode = "Basic Auth"
    }
    else {
        $script:Headers = @{
            Authorization = "Bearer $Password"
        }

        $authMode = "Bearer Token"
    }

    Write-Host "`n=== Artifactory Permission Audit ===" -ForegroundColor Cyan
    Write-Host "Target: $script:BaseUrl"
    Write-Host "Auth:   $authMode"

    Write-Host "`n[1] Identity" -ForegroundColor Cyan

    $me = Invoke-ArtifactoryApi `
        -Path "api/security/me" `
        -Headers $script:Headers

    if ($me.Error) {
        Write-Host "[-] Konnte Identität nicht abfragen." -ForegroundColor Red
        $me | Format-List
    }
    else {
        $me | Format-List
    }

    Write-Host "`n[2] Global Permission Indicators" -ForegroundColor Cyan

    $globalChecks = @(
        Test-ArtifactoryEndpoint "Read own identity"  "GET" "api/security/me"          "User kann eigene Identität lesen"
        Test-ArtifactoryEndpoint "List repositories" "GET" "api/repositories"         "User kann Repositories sehen"
        Test-ArtifactoryEndpoint "List users"        "GET" "api/security/users"       "Security-Read/Admin-Indikator"
        Test-ArtifactoryEndpoint "List groups"       "GET" "api/security/groups"      "Security-Read/Admin-Indikator"
        Test-ArtifactoryEndpoint "List permissions"  "GET" "api/security/permissions" "Permission-Read/Admin-Indikator"
        Test-ArtifactoryEndpoint "System ping"       "GET" "api/system/ping"          "System erreichbar"
        Test-ArtifactoryEndpoint "System version"    "GET" "api/system/version"       "System-Info lesbar"
        Test-ArtifactoryEndpoint "Storage info"      "GET" "api/storageinfo"          "Storage-/Admin-Info lesbar"
    )

    $globalChecks | Format-Table -AutoSize

    Write-Host "`n[3] Repository Visibility" -ForegroundColor Cyan

    $repos = Invoke-ArtifactoryApi `
        -Path "api/repositories" `
        -Headers $script:Headers

    if ($repos.Error) {
        Write-Host "[-] Keine Repository-Liste abrufbar." -ForegroundColor Yellow
        $repos | Format-List
        return
    }

    $repos |
        Select-Object key, type, packageType, description |
        Sort-Object key |
        Format-Table -AutoSize

    Write-Host "`n[4] Effective Repository Rights Matrix" -ForegroundColor Cyan

    $matrix = @()

    foreach ($repo in $repos) {

        $repoName = $repo.key

        $readRoot = Invoke-ArtifactoryApi `
            -Method "GET" `
            -Path "api/storage/$repoName" `
            -Headers $script:Headers

        $canRead = -not $readRoot.Error

        $search = Invoke-ArtifactoryApi `
            -Method "GET" `
            -Path "api/search/artifact?name=*&repos=$repoName" `
            -Headers $script:Headers

        $canSearch = -not $search.Error

        $canDeploy = "Not tested"
        $canDeleteOwnTestFile = "Not tested"

        if ($TestDeploy) {

            $testPath = "$repoName/__permission_test__/permission-test-$([guid]::NewGuid()).txt"

            $body = "permission test $(Get-Date -Format o)"

            $deploy = Invoke-ArtifactoryApi `
                -Method "PUT" `
                -Path $testPath `
                -Headers $script:Headers `
                -Body $body `
                -ContentType "text/plain"

            if (-not $deploy.Error) {

                $canDeploy = "YES"

                $delete = Invoke-ArtifactoryApi `
                    -Method "DELETE" `
                    -Path $testPath `
                    -Headers $script:Headers

                $canDeleteOwnTestFile = if ($delete.Error) { "NO" } else { "YES" }
            }
            else {
                $canDeploy = "NO"
                $canDeleteOwnTestFile = "Not applicable"
            }
        }

        $matrix += [PSCustomObject]@{
            Repository       = $repoName
            Type             = $repo.type
            PackageType      = $repo.packageType
            CanReadRoot      = if ($canRead) { "YES" } else { "NO" }
            CanSearch        = if ($canSearch) { "YES" } else { "NO" }
            CanDeploy        = $canDeploy
            CanDeleteOwnFile = $canDeleteOwnTestFile
        }
    }

    $matrix |
        Sort-Object Repository |
        Format-Table -AutoSize

    Write-Host "`n[+] Exportiere Ergebnisse..." -ForegroundColor Cyan

    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $matrix       | Export-Csv "$OutputDir\repo-rights-matrix.csv" -NoTypeInformation -Encoding UTF8
    $globalChecks | Export-Csv "$OutputDir\global-checks.csv" -NoTypeInformation -Encoding UTF8

    Write-Host "`n[+] Fertig." -ForegroundColor Green
}
