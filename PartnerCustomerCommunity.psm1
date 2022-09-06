using namespace Microsoft.Store.PartnerCenter
using namespace Microsoft.Store.PartnerCenter.Models
using namespace Microsoft.Store.PartnerCenter.Extensions

# Install-Package -Name 'Microsoft.Store.PartnerCenter' -SkipDependencies -Verbose -Scope CurrentUser
# Install-Package -Name 'Microsoft.Identity.Client' -SkipDependencies -Verbose -Scope CurrentUser
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Identity.Client.4.46.1\lib\netcoreapp2.1\Microsoft.Identity.Client.dll" '.\lib\'
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Store.PartnerCenter.3.1.2\lib\netstandard2.0\Microsoft.Store.PartnerCenter.dll" '.\lib\'
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Store.PartnerCenter.3.1.2\lib\netstandard2.0\Microsoft.Store.PartnerCenter.Models.dll" '.\lib\'
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Store.PartnerCenter.3.1.2\lib\netstandard2.0\Microsoft.Store.PartnerCenter.Extensions.dll" '.\lib\'
# Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Identity.Client.dll")
# Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Store.PartnerCenter.dll")
# Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Store.PartnerCenter.Models.dll")
# Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Store.PartnerCenter.Extensions.dll")

if (!(Get-Module -Name 'PSRunspacedDelegate')) {
    Import-Module -Name "$PSScriptRoot\PSRunspacedDelegate"
}
$ErrorActionPreference = 'Stop'

function Write-DebugObject {
    [CmdletBinding()]
    param (
        $Message
    )
    if ($DebugPreference -in 'Continue', 'Inquire', 'Stop') {
        if ($Message -is [string]) {
            if ($Message.Length -gt 8) {
                $NewMessage = $Message.Substring(0, 4) + '***' + $Message.Substring($Message.Length - 4, 4)
            }
            else {
                $NewMessage = $Message
            }
            Write-Debug $NewMessage
        }
        elseif ($Message -is [PSCustomObject]) {
            $NewMessage = $Message.PsObject.Copy()
            foreach ($Property in $NewMessage.PsObject.Properties) {
                if ($Property.Value -is [string] -and $Property.Value.Length -gt 8) {
                    $Property.Value = $Property.Value.Substring(0, 4) + '***' + $Property.Value.Substring($Property.Value.Length - 4, 4)
                }
            }
            Write-Debug ($NewMessage | Format-List | Out-String)
        }
        else {
            throw "Write-DebugObject: $($Message.GetType()) is not a string or a PSCustomObject"
        }
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

        [ValidateSet('Raw', 'Minimal')]
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

    if ($OutputFormat -eq 'Raw') {
        $ReturnCred
    }
    elseif ($OutputFormat -eq 'Minimal') {
        [PSCustomObject][ordered]@{
            AccessTokenExpiration = [DateTimeOffset]::FromUnixTimeSeconds($ReturnCred.expires_on).LocalDateTime
            AccessToken           = $ReturnCred.access_token
            RefreshToken          = $ReturnCred.refresh_token
        }
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
    [CmdletBinding()]
    param(
        # Limit to specific tenant.
        [string]$Tenant = 'common',

        # Your CSP/Partner Center application/Client ID.
        [Parameter(Mandatory)]
        [string]$ApplicationId,

        # Scope of the RefreshToken. Each endpoint needs its own consented RefreshToken.
        [ArgumentCompleter({
                'user.read', 'openid', 'profile',
                'https://api.partnercenter.microsoft.com/user_impersonation',
                'https://outlook.office365.com/.default'
            })]
        [string[]]$Scopes = @('https://api.partnercenter.microsoft.com/user_impersonation'),

        # Authorization grant flow.
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        [ValidateSet('OIDC', 'DeviceCode')]
        [string]$AuthenticationFlow = 'DeviceCode',

        [ValidateSet('Raw', 'OnlyRefreshToken')]
        [string]$OutputFormat = 'OnlyRefreshToken'
    )
    if (!$Tenant) {
        $Tenant = 'common'
    }

    $CodeBody = @{
        client_id = $ApplicationId
        scope     = $Scopes -join ' '
    }

    if ($AuthenticationFlow -eq 'DeviceCode') {
        # Get the authorization code.
        $AuthorizationCodeResponse = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/devicecode" -Body $CodeBody
        Write-Warning $AuthorizationCodeResponse.message

        # Get the RefreshToken.
        $RefreshTokenBody = @{
            grant_type = 'urn:ietf:params:oauth:grant-type:device_code'
            code       = $AuthorizationCodeResponse.device_code
            client_id  = $ApplicationId
        }
        while ([string]::IsNullOrEmpty($RefreshTokenResponse.access_token)) {
            Start-Sleep -Seconds 5
            $RefreshTokenResponse = try {
                Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" -Body $RefreshTokenBody
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
        throw '"-AuthenticationFlow OIDC" is not supported yet.'
    }

    if ($OutputFormat -eq 'Raw') {
        $RefreshTokenResponse
    }
    elseif ($OutputFormat -eq 'OnlyRefreshToken') {
        $RefreshTokenResponse.refresh_token
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
        # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code
        [ValidateSet('OIDC', 'DeviceCode')]
        [string]$AuthenticationFlow = 'OIDC',

        # Use this if you need the WebApp to support `New-PartnerRefreshToken -AuthenticationFlow DeviceCode`
        [switch]$IsFallbackPublicClient,

        # Stay connected to MgGraph.
        [switch]$StayConnected,

        [ValidateSet('Raw', 'Minimal')]
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
    $Application = New-MgApplication -DisplayName $DisplayName -RequiredResourceAccess ($AdAppAccess, $GraphAppAccess, $PartnerCenterAppAccess) -IsFallbackPublicClient:$IsFallbackPublicClient -SignInAudience 'AzureADMultipleOrgs' -Web @{
        RedirectUris = @("urn:ietf:wg:oauth:2.0:oob", "https://login.microsoftonline.com/organizations/oauth2/nativeclient", "https://localhost", "http://localhost", "http://localhost:8400")
    }

    $ApplicationPassword = Add-MgApplicationPassword -ApplicationId $Application.Id

    $ServicePrincipal = New-MgServicePrincipal -AppId $Application.AppId -DisplayName $DisplayName
    $AdminAgentsGroup = Get-MgGroup -Filter "DisplayName eq 'AdminAgents'"
    $null = $ServicePrincipal | New-MgGroupMember -GroupId $AdminAgentsGroup.Id

    if (!$StayConnected) {
        Write-Host "Disconnecting from Microsoft Graph"
        $null = Disconnect-MgGraph
    }

    if ($OutputFormat -eq 'Raw') {
        [PSCustomObject][ordered]@{
            ApplicationPassword = $ApplicationPassword
            Application         = $Application
        }
    }
    elseif ($OutputFormat -eq 'Minimal') {
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
        [string]$Tenant = 'common'
    )
    if (!$Tenant) {
        $Tenant = 'common'
    }

    $AccessToken = New-PartnerAccessToken -Credential $Credential -RefreshToken $RefreshToken -Tenant $Tenant

    $ApplicationId = $Credential.UserName

    class ScriptBlockDelegate {
        [ScriptBlock]$Code
        $DebugPreferenceParent = $DebugPreference

        ScriptBlockDelegate([ScriptBlock]$Code) {
            $this.Code = $Code
        }
        [System.Threading.Tasks.Task[Microsoft.Store.PartnerCenter.AuthenticationToken]]Delegate([Microsoft.Store.PartnerCenter.AuthenticationToken]$ExpiredAuthenticationToken) {
            $DebugPreference = $this.DebugPreferenceParent
            Write-Debug "ScriptBlockDelegate Delegate: Started"
            $Func = New-RunspacedDelegate ([Func[object, Microsoft.Store.PartnerCenter.AuthenticationToken]] $this.Code)
            Return [System.Threading.Tasks.TaskFactory[Microsoft.Store.PartnerCenter.AuthenticationToken]]::new().StartNew($Func, $ExpiredAuthenticationToken)
        }
    }
    $Callback = {
        param (
            [Microsoft.Store.PartnerCenter.AuthenticationToken]$ExpiredAuthenticationToken
        )
        $AccessToken = New-PartnerAccessToken -Credential $Credential -RefreshToken $RefreshToken -Tenant $Tenant
        # Write-DebugObject $AccessToken -Debug:$DebugPreference
        [Microsoft.Store.PartnerCenter.AuthenticationToken]::new($AccessToken.AccessToken, $AccessToken.AccessTokenExpiration) # Debug: ([DateTimeOffset]::Now.AddSeconds(32))
    }.GetNewClosure()
    $Delegate = [ScriptBlockDelegate]::new($Callback)
    $TokenRefresher = $Delegate.Delegate

    $PartnerCredentials = [Microsoft.Store.PartnerCenter.Extensions.PartnerCredentials]::Instance.GenerateByUserCredentials(
        $ApplicationId,
        [Microsoft.Store.PartnerCenter.AuthenticationToken]::new($AccessToken.AccessToken, $AccessToken.AccessTokenExpiration), # Debug: ([DateTimeOffset]::Now.AddSeconds(32))
        $TokenRefresher,
        $null
    )
    $Script:PartnerOperations = [Microsoft.Store.PartnerCenter.PartnerService]::Instance.CreatePartnerOperations($PartnerCredentials)
    Return $Script:PartnerOperations
}

function Get-PartnerOrganizationProfile {
    <#
        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/get-an-organization-profile#c
    #>
    [CmdletBinding()]
    [OutputType('Microsoft.Store.PartnerCenter.Models.Partners.OrganizationProfile')]
    param (
        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'

    Return $PartnerOperations.Profiles.OrganizationProfile.$Get()
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

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    if ($IndirectResellerId) {
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
        # $SubscriptionId

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    $PartnerOperations.Customers.ById($CustomerId).Subscriptions.$Get().Items
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

        # Return Task instead of result to support fast parallel execution.
        [switch]$Async,

        # PartnerOperations session, if not provided last generated one will be automatically used.
        $PartnerOperations = $Script:PartnerOperations
    )
    $Get = $Async ? 'GetAsync' : 'Get'
    if ($InputObject) {
        $CustomerId = $InputObject.Id
    }

    if ($CustomerId) {
        $PartnerOperations.Customers.ById($CustomerId).Relationships.$Get().Items
    }
    else {
        $PartnerOperations.Relationships.$Get([Relationships.PartnerRelationshipType]::IsIndirectCloudSolutionProviderOf).Items
    }
}