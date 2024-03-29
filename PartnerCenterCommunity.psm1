using namespace Microsoft.Store.PartnerCenter
using namespace Microsoft.Store.PartnerCenter.Models
using namespace Microsoft.Store.PartnerCenter.Extensions

if (!(Get-Module -Name 'PSRunspacedDelegate')) {
    Import-Module -Name "$PSScriptRoot\PSRunspacedDelegate"
}
$ErrorActionPreference = 'Stop'

function Write-DebugObject {
    [CmdletBinding()]
    param (
        $Messages,
        $Subject
    )
    if ($DebugPreference -in 'Continue', 'Inquire', 'Stop') {
        $NewMessages = foreach ($Message in $Messages) {
            if ($Message -is [string]) {
                if ($Message.Length -gt 8) {
                    $Message.Substring(0, 4) + '***' + $Message.Substring($Message.Length - 4, 4)
                }
                else {
                    $Message
                }
            }
            elseif ($Message -is [PSCustomObject]) {
                $NewMessage = $Message.PsObject.Copy()
                foreach ($Property in $NewMessage.PsObject.Properties) {
                    if ($Property.Value -is [string] -and $Property.Value.Length -gt 8) {
                        $Property.Value = $Property.Value.Substring(0, 4) + '***' + $Property.Value.Substring($Property.Value.Length - 4, 4)
                    }
                }
                ($NewMessage | Format-List | Out-String).Trim()
            }
            else {
                throw "Write-DebugObject: $($Message.GetType()) is not a string or a PSCustomObject"
            }
        }
        Write-Debug ($Subject, $NewMessages | Join-String -Separator ([Environment]::NewLine))
    }
}

function New-PartnerAccessToken {
    <#
        .OUTPUTS
        [String] Temporary token.
        [DateTimeOffset] Temporary token expiration time.

        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/enable-secure-app-model#get-access-token
        https://www.powershellgallery.com/packages/PartnerCenterLW/1.1
    #>
    [CmdletBinding()]
    param (
        # Application ID and secret.
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        # User token MFA authenticated.
        [Parameter(Mandatory)]
        [String]$RefreshToken,

        # Limit to specific tenant.
        [string]$Tenant = 'common',

        [ValidateSet('Raw', 'Minimal', 'FlatAutoFull')]
        [string]$OutputFormat = 'Minimal'
    )
    if (!$Tenant) {
        $Tenant = 'common'
    }

    $AuthBody = @{
        client_id     = $Credential.UserName
        refresh_token = $RefreshToken
        grant_type    = "refresh_token"
        client_secret = $Credential.GetNetworkCredential().Password
    }
    $Uri = "https://login.microsoftonline.com/$Tenant/oauth2/token"

    $ReturnCred = Invoke-RestMethod -Uri $Uri -ContentType "application/x-www-form-urlencoded" -Method POST -Body $AuthBody -ErrorAction Stop

    if ($OutputFormat -eq 'Minimal') {
        [PSCustomObject][ordered]@{
            AccessTokenExpiration = [DateTimeOffset]::FromUnixTimeSeconds($ReturnCred.expires_on).LocalDateTime
            AccessToken           = $ReturnCred.access_token
            RefreshToken          = $ReturnCred.refresh_token
        }
    }
    else {
        $ReturnCred | Format-Output -OutputFormat $OutputFormat
    }
}

function New-PartnerRefreshToken {
    <#
        .SYNOPSIS
        Uses device code flow to get a refresh token for the Partner Center API.

        .DESCRIPTION
        Gets a refresh token for the Partner Center API using an authorization code (with device code flow) and a second call to get the refresh token.

        .EXAMPLE
        New-PartnerRefreshToken -Tenant $Tenant -ApplicationId $ApplicationId

        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/enable-secure-app-model
    #>
    [CmdletBinding(DefaultParameterSetName = 'OIDC')]
    [CmdletBinding()]
    param(
        # Limit to specific tenant.
        [string]$Tenant = 'common',

        # Your CSP/Partner Center application/Client ID.
        [Parameter(ParameterSetName = 'DeviceCode', Mandatory)]
        [string]$ApplicationId,

        # Application ID and secret.
        [Parameter(ParameterSetName = 'OIDC', Mandatory)]
        [PSCredential]$Credential,

        # Scope of the RefreshToken. Each endpoint needs its own consented RefreshToken.
        [ArgumentCompleter({
                'user.read', 'openid', 'profile', 'offline_access',
                'https://api.partnercenter.microsoft.com/user_impersonation',
                'https://outlook.office365.com/.default'
            })]
        [string[]]$Scopes = @('https://api.partnercenter.microsoft.com/user_impersonation', 'offline_access', 'openid', 'profile'),

        # Authorization grant flow.
        # OIDC       - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
        # DeviceCode - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        [ValidateSet('OIDC', 'DeviceCode')]
        [string]$AuthenticationFlow = 'OIDC',

        [ValidateSet('Raw', 'OnlyRefreshToken', 'FlatAutoFull')]
        [string]$OutputFormat = 'OnlyRefreshToken'
    )
    if (!$Tenant) {
        $Tenant = 'common'
    }
    if ($AuthenticationFlow -eq 'DeviceCode' -and !($ApplicationId)) {
        throw "`New-PartnerRefreshToken -ApplicationId` is required when using `-AuthenticationFlow DeviceCode`."
    }
    elseif ($AuthenticationFlow -eq 'OIDC' -and !($Credential)) {
        throw "`New-PartnerRefreshToken -Credential` is required when using `-AuthenticationFlow OIDC`."
    }

    if ($AuthenticationFlow -eq 'DeviceCode') {
        # Get the authorization code.
        $CodeBody = @{
            client_id = $ApplicationId
            scope     = $Scopes -join ' '
        }
        $AuthorizationCodeResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/devicecode" -Body $CodeBody
        Write-Warning $AuthorizationCodeResponse.message

        # Get the RefreshToken.
        $RefreshTokenBody = @{
            grant_type  = 'urn:ietf:params:oauth:grant-type:device_code'
            device_code = $AuthorizationCodeResponse.device_code
            client_id   = $ApplicationId
        }
        while ([string]::IsNullOrEmpty($RefreshTokenResponse.access_token)) {
            Start-Sleep -Seconds 5
            $RefreshTokenResponse = try {
                Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Body $RefreshTokenBody
            }
            catch {
                $ErrorMessage = $_.ErrorDetails.Message | ConvertFrom-Json
                # If not waiting for auth, throw error
                if ($ErrorMessage.error -ne "authorization_pending") {
                    if ($ErrorMessage.error_description -like '*AADSTS7000218*') {
                        throw ('"-AuthenticationFlow DeviceCode" requires "Allow public client flows" in Azure Portal -> "App registrations" -> "Authentication". Original Error:' + [Environment]::NewLine + $_.ErrorDetails.Message)
                    }
                    throw $_
                }
            }
        }
    }
    elseif ($AuthenticationFlow -eq 'OIDC') {
        $Module = 'Pode'
        if (!((Get-Module -Name $Module -ListAvailable) -or (Get-Module -Name $Module))) {
            Install-Module $Module
        }
        $PodeModule = (Get-Module -Name $Module).Path

        $PodeJob = Start-Job {
            Import-Module $using:PodeModule
            $UsedPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
            $Port = [Linq.Enumerable]::First([Linq.Enumerable]::Except([Linq.Enumerable]::Range(8400, 600), [int[]]$UsedPorts.LocalPort))
            @{ Port = $Port }
            Start-PodeServer -Quiet {
                Add-PodeEndpoint -Address localhost -Port $Port -Protocol Http
                Add-PodeRoute -Method POST -Path '/' -ScriptBlock {
                    Write-PodeJsonResponse -Value $WebEvent.Data
                    Out-PodeVariable -Name Code -Value $WebEvent.Data.code
                    Close-PodeServer
                }
            }
            @{ Code = $Code }
        }
        while ($PodeJob.State -eq 'Running') {
            $PodeJob | Receive-Job | ForEach-Object {
                if ($_.Port) {
                    $Port = $_.Port
                    break
                }
                else {
                    Write-Warning ($_ | Format-List | Out-String)
                }
            }
            Start-Sleep -Seconds 0.2
        }
        $Uri = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/authorize"
        $ParametersCode = @{
            client_id     = $Credential.UserName
            response_mode = 'form_post'
            response_type = 'code id_token'
            scope         = $Scopes -join ' '
            nonce         = 1
            redirect_uri  = "http://localhost:$port/"
            prompt        = 'select_account'
        }
        # Build the URI.
        $ParametersCodeCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        foreach ($key in $ParametersCode.Keys) {
            $ParametersCodeCollection.Add($key, $ParametersCode.$key)
        }
        $UriRequest = [System.UriBuilder]$Uri
        $UriRequest.Query = $ParametersCodeCollection.ToString()

        Start-Process $UriRequest
        $Code = $null
        $PodeJob | Receive-Job -Wait | ForEach-Object {
            if ($_.Code) {
                $Code = $_.Code
            }
            else {
                Write-Warning ($_ | Format-List | Out-String)
            }
        }
        if (!$Code) {
            throw 'Failed to get the authorization code.'
        }

        $Uri = "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token"
        $RefreshTokenParameters = @{
            client_id     = $Credential.UserName
            client_secret = $Credential.GetNetworkCredential().Password
            grant_type    = "authorization_code"
            code          = $Code
            redirect_uri  = "http://localhost:$port/"
        }
        $RefreshTokenResponse = Invoke-RestMethod -Uri $Uri -ContentType "application/x-www-form-urlencoded" -Method POST -Body $RefreshTokenParameters
    }

    if ($OutputFormat -eq 'OnlyRefreshToken') {
        $RefreshTokenResponse.refresh_token
    }
    else {
        $RefreshTokenResponse | Format-Output -OutputFormat $OutputFormat
    }
}

function New-PartnerWebApp {
    <#
        .SYNOPSIS
        Creates a new Azure web app for Partner Center.

        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/enable-secure-app-model#create-a-web-app
        Updated version of https://www.cyberdrain.com/connect-to-exchange-online-automated-when-mfa-is-enabled-using-the-secureapp-model/
    #>
    [CmdletBinding()]
    param(
        # Limit to specific tenant.
        [string]$Tenant,

        [Parameter(Mandatory)]
        [string]$DisplayName,

        # Authorization grant flow.
        # OIDC       - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc
        # DeviceCode - https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        [ValidateSet('OIDC', 'DeviceCode')]
        [string]$AuthenticationFlow = 'OIDC',

        # OIDC       - If you need the WebApp to support `New-PartnerRefreshToken -AuthenticationFlow OIDC` (EnableIdTokenIssuance).
        # DeviceCode - If you need the WebApp to support `New-PartnerRefreshToken -AuthenticationFlow DeviceCode` (IsFallbackPublicClient).
        [ValidateSet('OIDC', 'DeviceCode')]
        [string[]]$AuthenticationFlowAllowed = 'OIDC',

        # Stay connected to MgGraph.
        [switch]$StayConnected,

        [ValidateSet('Raw', 'Minimal', 'FlatAutoFull')]
        [string]$OutputFormat = 'Minimal'
    )

    # Check if the Azure AD PowerShell module has already been loaded.
    $Modules = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications', 'Microsoft.Graph.Groups'
    $ModulesToImport = @()
    $ModulesToInstall = @()
    foreach ($Module in $Modules) {
        if (!(Get-Module -Name $Module)) {
            # Check if the Azure AD PowerShell module is installed.
            if (Get-Module -Name $Module -ListAvailable) {
                # The Azure AD PowerShell module is not load and it is installed. This module # must be loaded for other operations performed by this script.
                $ModulesToImport += $Module
            }
            else {
                $ModulesToInstall += $Module
            }
        }
    }
    if ($ModulesToImport) {
        Write-Host -ForegroundColor Green "Loading the $ModulesToImport PowerShell modules..."
        Import-Module $ModulesToImport
    }
    elseif ($ModulesToInstall) {
        Write-Host -ForegroundColor Green "Installing the $ModulesToInstall PowerShell modules..."
        Install-Module $ModulesToInstall
    }

    $MgGraphParams = @{ Scopes = 'Application.ReadWrite.All', 'User.Read', 'Group.Read.All', 'GroupMember.ReadWrite.All' }
    if ($AuthenticationFlow -eq 'DeviceCode') {
        $MgGraphParams['UseDeviceAuthentication'] = $true
    }
    if ($Tenant) {
        $MgGraphParams['TenantId'] = $Tenant
    }
    Write-Host -ForegroundColor Green "When prompted please enter the appropriate credentials... Warning: Window might have pop-under in VSCode"
    Connect-MgGraph @MgGraphParams | ForEach-Object {
        if ($_ -eq 'Welcome To Microsoft Graph!') {
            Write-Host -ForegroundColor Green $_
        }
        else {
            Write-Warning $_
        }
    }

    $AdAppAccess = @{
        ResourceAppId  = "00000002-0000-0000-c000-000000000000";
        ResourceAccess = @(
            @{
                Id   = "5778995a-e1bf-45b8-affa-663a9f3f4d04";
                Type = "Role"
            },
            @{
                Id   = "a42657d6-7f20-40e3-b6f0-cee03008a62a";
                Type = "Scope"
            },
            @{
                Id   = "311a71cc-e848-46a1-bdf8-97ff7156d8e6";
                Type = "Scope"
            }
        )
    }

    $GraphAppAccess = @{
        ResourceAppId  = "00000003-0000-0000-c000-000000000000";
        ResourceAccess = @(
            @{
                Id   = "bf394140-e372-4bf9-a898-299cfc7564e5";
                Type = "Role"
            },
            @{
                Id   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61";
                Type = "Role"
            }
        )
    }

    $PartnerCenterAppAccess = @{
        ResourceAppId  = "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd";
        ResourceAccess = @(
            @{
                Id   = "1cebfa2a-fb4d-419e-b5f9-839b4383e05a";
                Type = "Scope"
            }
        )
    }

    Write-Host -ForegroundColor Green "Creating the Azure AD application and related resources..."
    $ApplicationParams = @{
        DisplayName            = $DisplayName
        RequiredResourceAccess = ($AdAppAccess, $GraphAppAccess, $PartnerCenterAppAccess)
        SignInAudience         = 'AzureADMultipleOrgs'
        Web                    = @{
            RedirectUris          = @("urn:ietf:wg:oauth:2.0:oob", "https://login.microsoftonline.com/organizations/oauth2/nativeclient", "https://localhost", "http://localhost", "http://localhost:8400")
            ImplicitGrantSettings = @{
                EnableIdTokenIssuance = $true
            }
        }
    }
    if ($AuthenticationFlowAllowed -contains 'DeviceCode') {
        $ApplicationParams['IsFallbackPublicClient'] = $true
    }
    if ($AuthenticationFlowAllowed -contains 'OIDC') {
        $ApplicationParams['Web']['ImplicitGrantSettings'] = @{
            EnableIdTokenIssuance = $true
        }
    }
    $Application = New-MgApplication @ApplicationParams

    $ApplicationPassword = Add-MgApplicationPassword -ApplicationId $Application.Id

    $ServicePrincipal = New-MgServicePrincipal -AppId $Application.AppId -DisplayName $DisplayName
    $AdminAgentsGroup = Get-MgGroup -Filter "DisplayName eq 'AdminAgents'"
    $null = $ServicePrincipal | New-MgGroupMember -GroupId $AdminAgentsGroup.Id

    if (!$StayConnected) {
        Write-Host "Disconnecting from Microsoft Graph"
        $null = Disconnect-MgGraph
    }

    if ($OutputFormat -eq 'Minimal') {
        $SecretSecureString = $ApplicationPassword.SecretText | ConvertTo-SecureString -AsPlainText -Force
        $Output = [ordered]@{
            Credential       = [System.Management.Automation.PSCredential]::new($Application.AppId, $SecretSecureString)
            SecretExpiration = $ApplicationPassword.EndDateTime
        }
        if ($Tenant) {
            $Output['Tenant'] = $Tenant
        }
        [PSCustomObject]$Output
    }
    else {
        [PSCustomObject][ordered]@{
            ApplicationPassword = $ApplicationPassword
            Application         = $Application
        } | Format-Output -OutputFormat $OutputFormat
    }
}

function Connect-PartnerCenter {
    <#
        .OUTPUTS
        PartnerOperations object that can be used to perform operations on the Partner Center API.

        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/partner-center-authentication#app--user-authentication
    #>
    [CmdletBinding()]
    [OutputType('Microsoft.Store.PartnerCenter.AggregatePartnerOperations')]
    param (
        # Application ID and secret.
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        # User token MFA authenticated.
        [Parameter(Mandatory)]
        [String]$RefreshToken,

        # Limit to specific tenant.
        [string]$Tenant = 'common',

        # # This script will run on "access token" refresh, can be used to save the now generated extended "refresh token" for next time.
        [scriptblock]$RefreshTokenScript
    )
    if (!$Tenant) {
        $Tenant = 'common'
    }

    $AccessToken = New-PartnerAccessToken -Credential $Credential -RefreshToken $RefreshToken -Tenant $Tenant

    $ApplicationId = $Credential.UserName

    class ScriptBlockDelegate {
        $DebugPreferenceParent = $DebugPreference
        [PSCredential]$Credential
        [string]$RefreshToken
        [string]$Tenant
        [ScriptBlock]$RefreshTokenScript

        ScriptBlockDelegate(
            [PSCredential]$Credential,
            [string]$RefreshToken,
            [string]$Tenant,
            [ScriptBlock]$RefreshTokenScript
        ) {
            $this.Credential = $Credential
            $this.RefreshToken = $RefreshToken
            $this.Tenant = $Tenant
            $this.RefreshTokenScript = $RefreshTokenScript
        }
        [System.Threading.Tasks.Task[Microsoft.Store.PartnerCenter.AuthenticationToken]]Delegate([Microsoft.Store.PartnerCenter.AuthenticationToken]$ExpiredAuthenticationToken) {
            $DebugPreference = $this.DebugPreferenceParent
            $AccessToken = New-PartnerAccessToken -Credential $this.Credential -RefreshToken $this.RefreshToken -Tenant $this.Tenant
            Write-DebugObject $AccessToken -Subject 'AccessToken refreshed:'
            $this.RefreshToken = $AccessToken.RefreshToken
            if ($this.RefreshTokenScript) {
                $null = & $this.RefreshTokenScript $AccessToken
            }

            $AuthenticationToken = [Microsoft.Store.PartnerCenter.AuthenticationToken]::new($AccessToken.AccessToken, $AccessToken.AccessTokenExpiration) # Debug: ([DateTimeOffset]::Now.AddSeconds(32))
            $Callback = { $AuthenticationToken }.GetNewClosure()
            $Func = New-RunspacedDelegate ([Func[object, Microsoft.Store.PartnerCenter.AuthenticationToken]] $Callback)
            Return [System.Threading.Tasks.TaskFactory[Microsoft.Store.PartnerCenter.AuthenticationToken]]::new().StartNew($Func, $ExpiredAuthenticationToken)
        }
    }
    $Delegate = [ScriptBlockDelegate]::new($Credential, $RefreshToken, $Tenant, $RefreshTokenScript)
    $TokenRefresher = $Delegate.Delegate

    $PartnerCredentials = [Microsoft.Store.PartnerCenter.Extensions.PartnerCredentials]::Instance.GenerateByUserCredentials(
        $ApplicationId,
        [Microsoft.Store.PartnerCenter.AuthenticationToken]::new($AccessToken.AccessToken, $AccessToken.AccessTokenExpiration), # Debug: ([DateTimeOffset]::Now.AddSeconds(32))
        $TokenRefresher,
        $null
    )
    $Script:PartnerOperations = [Microsoft.Store.PartnerCenter.PartnerService]::Instance.CreatePartnerOperations($PartnerCredentials)
    $Script:PartnerOperations
}
# # Wait for multithreading support https://github.com/PowerShell/PowerShell/pull/18138
# function Set-PartnerCenterConnection {
#     <#
#         .OUTPUTS
#         Set a PartnerOperations object as the default connection.
#     #>
#     [CmdletBinding()]
#     [OutputType('Microsoft.Store.PartnerCenter.AggregatePartnerOperations')]
#     param (
#         [Parameter(Mandatory)]
#         $PartnerOperations
#     )
#     $Script:PartnerOperations = $PartnerOperations
# }

function Get-PartnerOrganizationProfile {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-an-organization-profile#c
    #>
    [CmdletBinding()]
    [OutputType('Microsoft.Store.PartnerCenter.Models.Partners.OrganizationProfile')]
    param (
        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes', 'Compatibility')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'

    $OutputRaw = $PartnerOperations.Profiles.OrganizationProfile.$Get()

    if ($OutputFormat -eq 'Compatibility') {
        [PSCustomObject][ordered]@{
            Id             = $OutputRaw.Id
            CompanyName    = $OutputRaw.CompanyName
            DefaultAddress = $OutputRaw.DefaultAddress
            TenantId       = $OutputRaw.TenantId
            Domain         = $OutputRaw.Domain
            Email          = $OutputRaw.Email
            Language       = $OutputRaw.Language
            Culture        = $OutputRaw.Culture
        }
    }
    else {
        $OutputRaw | Format-Output -OutputFormat $OutputFormat
    }
}

function Get-PartnerOrganizationProfileRestExample {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-an-organization-profile#rest-request
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        $AccessToken
    )
    $ContentType = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f [System.Text.Encoding]::UTF8.WebName) -join ';'
    $Response = Invoke-RestMethod -ContentType $ContentType -Uri 'https://api.partnercenter.microsoft.com/v1/profiles/organization' -Headers @{
        "Authorization"    = "Bearer " + $AccessToken
        'Accept'           = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f ([System.Text.Encoding]::UTF8).WebName) -join ';'
        'MS-RequestId'     = 'b85cb7ab-cc2e-4966-93f0-cf0d8377a93f'
        'MS-CorrelationId' = '1bb03149-88d2-4bc2-9cc1-d6e83890fa9e'
    }
    $Response.Substring(1) | ConvertFrom-Json
}

function Get-PartnerCustomer {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-customers-of-an-indirect-reseller#c
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType('Microsoft.Store.PartnerCenter.Models.Customers.Customer')]
    param (
        # Customer object.
        [Parameter(ParameterSetName = 'PipeLine', Mandatory, ValueFromPipeLine)]
        $InputObject,

        # Customer tenant ID, if not provided will get all customers.
        [Parameter(ParameterSetName = 'Customer', Mandatory)]
        [String]$CustomerId,

        # Reseller tenant ID, if provided filter customers from specific reseller.
        [Parameter(ParameterSetName = 'IndirectReseller', Mandatory)]
        [String]$IndirectResellerId,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    $OutputRaw = if ($IndirectResellerId) {
        # Create a filter.
        $Filter = [Microsoft.Store.PartnerCenter.Models.Query.SimpleFieldFilter]::new(
            [Microsoft.Store.PartnerCenter.Models.Customers.CustomerSearchField]::IndirectReseller.ToString(),
            [Microsoft.Store.PartnerCenter.Models.Query.FieldFilterOperation]::StartsWith,
            $IndirectResellerId
        )

        # Create an iQuery object to pass to the Query method.
        $MyQuery = [Microsoft.Store.PartnerCenter.Models.Query.QueryFactory]::Instance.BuildSimpleQuery($Filter)

        # Get the collection of matching customers.
        $CustomersPage = $PartnerOperations.Customers.Query($MyQuery);

        # Create a customer enumerator for traversing the customer pages.
        $CustomersEnumerator = $PartnerOperations.Enumerators.Customers.Create($CustomersPage);
        while ($CustomersEnumerator.HasValue) {
            # Work with the current page.
            foreach ($Customer in $CustomersEnumerator.Current.Items) {
                $Customer
            }
            # Get the next page of customers.
            $CustomersEnumerator.Next()
        }
    }
    elseif ($CustomerId) {
        $PartnerOperations.Customers.ById($CustomerId).$Get()
    }
    else {
        $CustomersPage = $PartnerOperations.Customers.Get()

        # Create a customer enumerator for traversing the customer pages.
        $CustomersEnumerator = $PartnerOperations.Enumerators.Customers.Create($CustomersPage);
        while ($CustomersEnumerator.HasValue) {
            # Work with the current page.
            foreach ($Customer in $CustomersEnumerator.Current.Items) {
                $Customer
            }
            # Get the next page of customers.
            $CustomersEnumerator.Next()
        }
    }
    $OutputRaw | Format-Output -OutputFormat $OutputFormat
}

function Get-PartnerCustomerRestExample {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-customers-of-an-indirect-reseller#rest-request

        WARNING: This example missing a "paging" retrieval code so it will only return the first page of customers.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType('Microsoft.Store.PartnerCenter.Models.Customers.Customer')]
    param (
        [Parameter(Mandatory)]
        $AccessToken,
        # Customer tenant ID, if not provided will get all customers.
        [Parameter(ParameterSetName = 'Customer', Mandatory)]
        [String]$CustomerId,
        # Reseller tenant ID, if not provided filter customers from specific reseller.
        [Parameter(ParameterSetName = 'IndirectReseller', Mandatory)]
        [String]$IndirectResellerId
    )
    if ($IndirectResellerId) {
        $ContentType = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f [System.Text.Encoding]::UTF8.WebName) -join ';'
        $Response = Invoke-RestMethod -ContentType $ContentType -Uri ('https://api.partnercenter.microsoft.com/v1/customers?filter={{"field":"IndirectReseller","value":"{0}","operator":"starts_with"}}' -f $IndirectResellerId) -Headers @{
            "Authorization" = "Bearer " + $AccessToken
            'Accept'        = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f ([System.Text.Encoding]::UTF8).WebName) -join ';'
        }
        $Response
    }
    elseif ($CustomerId) {
        $ContentType = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f [System.Text.Encoding]::UTF8.WebName) -join ';'
        $Response = Invoke-RestMethod -ContentType $ContentType -Uri "https://api.partnercenter.microsoft.com/v1/customers/$CustomerId" -Headers @{
            "Authorization" = "Bearer " + $AccessToken
            'Accept'        = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f ([System.Text.Encoding]::UTF8).WebName) -join ';'
        }
        $Response
    }
    else {
        $ContentType = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f [System.Text.Encoding]::UTF8.WebName) -join ';'
        $Response = Invoke-RestMethod -ContentType $ContentType -Uri "https://api.partnercenter.microsoft.com/v1/customers" -Headers @{
            "Authorization" = "Bearer " + $AccessToken
            'Accept'        = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f ([System.Text.Encoding]::UTF8).WebName) -join ';'
        }
        $Response
    }
}

function Get-PartnerCustomerSubscription {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-all-subscriptions-by-partner#c
    #>
    [CmdletBinding()]
    [OutputType('Microsoft.Store.PartnerCenter.Models.Subscriptions.Subscription')]
    param (
        # Customer object.
        [Parameter(ParameterSetName = 'PipeLine', Mandatory, ValueFromPipeLine)]
        $InputObject,

        # Customer tenant ID.
        [Parameter(ParameterSetName = 'CustomerId', Mandatory)]
        [string]$CustomerId,

        # $MpnId

        # Customer Subscription ID.
        [string]$SubscriptionId,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    $OutputRaw = if ($SubscriptionId) {
        $PartnerOperations.Customers.ById($CustomerId).Subscriptions.ById($SubscriptionId).$Get()
    }
    else {
        $PartnerOperations.Customers.ById($CustomerId).Subscriptions.$Get().Items
    }
    $OutputRaw | Format-Output -OutputFormat $OutputFormat
}

function Get-PartnerIndirectReseller {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-indirect-resellers-of-a-customer#c
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType('Microsoft.Store.PartnerCenter.Models.Relationships.PartnerRelationship')]
    param (
        # Customer object.
        [Parameter(ParameterSetName = 'PipeLine', Mandatory, ValueFromPipeLine)]
        $InputObject,

        # Customer tenant ID.
        [Parameter(ParameterSetName = 'CustomerId', Mandatory)]
        [string]$CustomerId,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    $OutputRaw = if ($CustomerId) {
        $PartnerOperations.Customers.ById($CustomerId).Relationships.$Get().Items
    }
    else {
        $PartnerOperations.Relationships.$Get([Relationships.PartnerRelationshipType]::IsIndirectCloudSolutionProviderOf).Items
    }
    $OutputRaw | Format-Output -OutputFormat $OutputFormat
}

function Format-Output {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject,
        $OutputFormat
    )
    process {
        if ($OutputFormat -eq 'Raw') {
            $InputObject
        }
        elseif ($OutputFormat -eq 'FlatAutoFull') {
            $InputObject | Get-Flattened
        }
        elseif ($OutputFormat -eq 'FlatAutoNoLinksAttributes') {
            $InputObject | Get-Flattened -Filter 'Links', 'Attributes'
        }
        else {
            throw "Unhandled output format: $OutputFormat."
        }
    }
}

function Get-Flattened {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline)]
        $InputObject,
        $ObjectType,
        $Prefix,
        [string[]]$Filter = @(),
        $_Output
    )
    process {
        $ObjectType ??= $InputObject.GetType()
        if ($null -eq $_Output) {
            $Output = [ordered]@{}
            $First = $true
        }
        else {
            $First = $false
        }

        if ($ObjectType -eq [System.Management.Automation.PSCustomObject]) {
            foreach ($Property in $InputObject.PSObject.Properties) {
                $PropertyPrefix = ($Prefix, $Property.Name | Join-String -Separator '_')
                $PropertyType = $InputObject.($Property.Name)?.GetType()
                if ($null -eq $PropertyType) {
                    throw "PSCustomObject property ""$($Property.Name)"" is null, cannot flatten reliably."
                }
                if ($PropertyType.IsValueType -or $PropertyType -in [string], [DateTime], [System.Uri]) {
                    $Output[$PropertyPrefix] = $InputObject.($Property.Name)
                }
                else {
                    Get-Flattened -InputObject $InputObject.($Property.Name) -ObjectType $PropertyType -Prefix $PropertyPrefix -Filter $Filter -_Output $Output
                }
            }
        }
        else {
            foreach ($Property in $ObjectType.GetProperties()) {
                if ($Property.Name -in $Filter) {
                    continue
                }
                $PropertyPrefix = ($Prefix, $Property.Name | Join-String -Separator '_')
                if ($Property.PropertyType.IsValueType -or $Property.PropertyType -in [string], [DateTime], [System.Uri]) {
                    $Output[$PropertyPrefix] = $InputObject.($Property.Name)
                    continue
                }
                if ($Property.PropertyType.ImplementedInterfaces -contains [System.Collections.IEnumerable]) {
                    if (($Property.PropertyType.GenericTypeArguments | Select-Object -Unique).Count -eq 1) {
                        $SubType = $Property.PropertyType.GenericTypeArguments[0]
                    }
                    elseif ($Property.PropertyType.GenericTypeArguments.Count -gt 1) {
                        throw 'multiple sub types?'
                    }
                    elseif ($Property.PropertyType.FullName -like '*[[]]' -and ($SubType = $Property.PropertyType.FullName.Trim('[]') -as [type])) {
                    }
                    else {
                        throw 'unexpected sub types?'
                    }
                    if ($SubType.IsValueType -or $SubType -in [string], [DateTime], [System.Uri]) {
                        $Output[$PropertyPrefix] = $InputObject.($Property.Name) -join ', '
                        continue
                    }
                    else {
                        Get-Flattened -InputObject $InputObject.($Property.Name) -ObjectType $SubType -Prefix $PropertyPrefix -Filter $Filter -_Output $Output
                    }
                }
                else {
                    if ($Property.PropertyType -eq $ObjectType) {
                        if ($null -eq $InputObject.($Property.Name)) {
                            $Output[$PropertyPrefix] = $null
                        }
                        else {
                            throw 'recursive?'
                            # $Output[$PropertyPrefix] = $InputObject.($Property.Name)
                        }
                    }
                    else {
                        Get-Flattened -InputObject $InputObject.($Property.Name) -ObjectType $Property.PropertyType -Prefix $PropertyPrefix -Filter $Filter -_Output $Output
                    }
                }
            }
        }
        if ($First) {
            [PSCustomObject]$Output
        }
    }
}

function Get-PartnerCustomerOrder {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-an-order-by-id#c
    #>
    [OutputType('Microsoft.Store.PartnerCenter.Models.Subscriptions.Subscription')]
    param (
        # Customer object.
        [Parameter(ParameterSetName = 'PipeLine', Mandatory, ValueFromPipeLine)]
        $InputObject,

        # Customer tenant ID.
        [Parameter(ParameterSetName = 'CustomerId', Mandatory)]
        [string]$CustomerId,

        # Customer Order ID.
        [string]$OrderId,

        # Include Price.
        [bool]$IncludePrice,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    $OutputRaw = if ($OrderId) {
        $PartnerOperations.Customers.ById($CustomerId).Orders.ById($OrderId).$Get($IncludePrice)
    }
    else {
        $PartnerOperations.Customers.ById($CustomerId).Orders.$Get($IncludePrice).Items
    }
    $OutputRaw | Format-Output -OutputFormat $OutputFormat
}

function Get-PartnerTransitionEligibilities {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/transition-a-new-commerce-subscription
    #>
    [OutputType('Microsoft.Store.PartnerCenter.Models.Subscriptions.Subscription')]
    param (
        # Customer tenant ID.
        [Parameter(Mandatory)]
        [string]$CustomerId,

        # Customer Subscription ID.
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [ValidateSet('immediate', 'scheduled')]
        $EligibilityType,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'

    $PartnerOperations.Customers.ById($CustomerId).Subscriptions.ById($SubscriptionId).TransitionEligibilities.$Get($EligibilityType).Items | Format-Output -OutputFormat $OutputFormat
}

function New-PartnerTransition {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/transition-a-new-commerce-subscription
    #>
    [OutputType('Microsoft.Store.PartnerCenter.Models.Subscriptions.Subscription')]
    param (
        # Customer tenant ID.
        [Parameter(Mandatory)]
        [string]$CustomerId,

        # Customer Subscription ID.
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        # The catalog item you are transitioning to.
        [Parameter(Mandatory)]
        [string]$ToCatalogItemId,

        # The subscription ID you are transitioning to.
        [string]$ToSubscriptionId,

        # The number of licenses to transition over.
        [Parameter(Mandatory)]
        [int]$Quantity,

        # Specifying the term duration of the subscription.
        [ArgumentCompleter({ 'P1M', 'P1Y', 'P3Y' })]
        [string]$TermDuration,

        # Specifying the billing cycle of the subscription.
        [ArgumentCompleter({ 'Monthly', 'Annual', 'Triennial' })]
        [string]$BillingCycle,

        # The transition type. Possible values - transition_only, transition_with_license_transfer.
        [Parameter(Mandatory)]
        [ValidateSet('transition_only', 'transition_with_license_transfer')]
        [string]$TransitionType,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Create = $Async ? 'CreateAsync' : 'Create'

    $Transition = [Microsoft.Store.PartnerCenter.Models.Subscriptions.Transition]::new()
    $Transition.ToCatalogItemId = $ToCatalogItemId
    $Transition.Quantity = $Quantity
    $Transition.TransitionType = $TransitionType
    $Transition.ToSubscriptionId = $ToSubscriptionId
    $Transition.TermDuration = $TermDuration
    $Transition.BillingCycle = $BillingCycle

    $PartnerOperations.Customers.ById($CustomerId).Subscriptions.ById($SubscriptionId).Transitions.$Create($Transition) | Format-Output -OutputFormat $OutputFormat
}

function Get-PartnerTransition {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/transition-a-new-commerce-subscription
    #>
    param (
        # Customer tenant ID.
        [Parameter(Mandatory)]
        [string]$CustomerId,

        # Customer Subscription ID.
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [ValidateSet('Raw', 'FlatAutoFull', 'FlatAutoNoLinksAttributes')]
        [string]$OutputFormat = 'Raw',

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'

    $PartnerOperations.Customers.ById($CustomerId).Subscriptions.ById($SubscriptionId).Transitions.$Get() | Format-Output -OutputFormat $OutputFormat
}

function Get-PartnerCustomerCustomDomains {
    <#
        .NOTES
        https://learn.microsoft.com/en-us/partner-center/developer/get-customer-custom-domain
    #>
    [OutputType([string[]])]
    param (
        # Customer object.
        [Parameter(ParameterSetName = 'PipeLine', Mandatory, ValueFromPipeLine)]
        $InputObject,

        # Customer tenant ID.
        [Parameter(ParameterSetName = 'CustomerId', Mandatory)]
        [string]$CustomerId,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    # Send any request to update token if needed.
    Get-PartnerOrganizationProfile -PartnerOperations $PartnerOperations | Out-Null
    $AccessToken = $PartnerOperations.Credentials.PartnerServiceToken

    $ContentType = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f [System.Text.Encoding]::UTF8.WebName) -join ';'
    $Response = Invoke-RestMethod -ContentType $ContentType -Uri "https://api.partnercenter.microsoft.com/v1/customers/$CustomerId/customDomains" -Headers @{
        "Authorization"    = "Bearer " + $AccessToken
        'Accept'           = [System.Net.Mime.MediaTypeNames+Application]::Json, ('charset={0}' -f ([System.Text.Encoding]::UTF8).WebName) -join ';'
        'MS-RequestId'     = 'b85cb7ab-cc2e-4966-93f0-cf0d8377a93f'
        'MS-CorrelationId' = '1bb03149-88d2-4bc2-9cc1-d6e83890fa9e'
    }
    $Response
}
