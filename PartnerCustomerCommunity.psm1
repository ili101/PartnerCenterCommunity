using namespace Microsoft.Store.PartnerCenter
using namespace Microsoft.Store.PartnerCenter.Models
using namespace Microsoft.Store.PartnerCenter.Extensions

# Install-Package -Name 'Microsoft.Store.PartnerCenter' -SkipDependencies -Verbose -Scope CurrentUser
# Install-Package -Name 'Microsoft.Identity.Client' -SkipDependencies -Verbose -Scope CurrentUser
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Identity.Client.4.46.1\lib\netcoreapp2.1\Microsoft.Identity.Client.dll" '.\lib\'
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Store.PartnerCenter.3.1.2\lib\netstandard2.0\Microsoft.Store.PartnerCenter.dll" '.\lib\'
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Store.PartnerCenter.3.1.2\lib\netstandard2.0\Microsoft.Store.PartnerCenter.Models.dll" '.\lib\'
# Copy-Item "$env:LOCALAPPDATA\PackageManagement\NuGet\Packages\Microsoft.Store.PartnerCenter.3.1.2\lib\netstandard2.0\Microsoft.Store.PartnerCenter.Extensions.dll" '.\lib\'
Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Identity.Client.dll")
Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Store.PartnerCenter.dll")
Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Store.PartnerCenter.Models.dll")
Add-Type -Path (Resolve-Path -Path "$PSScriptRoot\lib\Microsoft.Store.PartnerCenter.Extensions.dll")

function New-PartnerAccessToken {
    <#
        .OUTPUTS
        [String] Temporary token.
        [DateTimeOffset] Temporary token expiration time.

        .NOTES
        https://www.powershellgallery.com/packages/PartnerCenterLW/1.1
    #>
    param (
        # Application ID and secret.
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        # User token MFA authenticated.
        [Parameter(Mandatory)]
        [String]$RefreshToken,

        # Limit to specific tenant.
        [string]$Tenant
    )

    $AuthBody = @{
        client_id     = $Credential.UserName
        refresh_token = $RefreshToken
        grant_type    = "refresh_token"
        client_secret = $Credential.GetNetworkCredential().Password
    }

    if ($Tenant) {
        $Uri = "https://login.microsoftonline.com/$Tenant/oauth2/token"
    }
    else {
        $Uri = "https://login.microsoftonline.com/common/oauth2/token"
    }

    $ReturnCred = Invoke-RestMethod -Uri $Uri -ContentType "application/x-www-form-urlencoded" -Method POST -Body $AuthBody -ErrorAction Stop

    # Return [Tuple[string, DateTimeOffset]]::new($ReturnCred.access_token, [DateTime]::UtcNow + [TimeSpan]::FromSeconds($ReturnCred.expires_in))
    Return $ReturnCred.access_token, [DateTimeOffset]::FromUnixTimeSeconds($ReturnCred.expires_on)
}

function Connect-PartnerCenter {
    <#
        .OUTPUTS
        PartnerOperations object that can be used to perform operations on the Partner Center API.

        .NOTES
        https://docs.microsoft.com/en-us/partner-center/develop/partner-center-authentication#app--user-authentication
    #>
    [OutputType('Microsoft.Store.PartnerCenter.AggregatePartnerOperations')]
    param (
        # Application ID and secret.
        [Parameter(Mandatory)]
        [PSCredential]$Credential,

        # User token MFA authenticated.
        [Parameter(Mandatory)]
        [String]$RefreshToken,

        # Limit to specific tenant.
        [string]$Tenant
    )
    $AccessToken = New-PartnerAccessToken -Credential $Credential -RefreshToken $RefreshToken -Tenant $Tenant

    $ApplicationId = $Credential.UserName

    $RefFolder = Join-Path ( Split-Path ([PSObject].Assembly.Location) ) "ref"
    $RefAssemblies = Get-ChildItem -Path $RefFolder -Filter "*.dll" | Select-Object -Expand FullName
    $ExtraAssemblies = [Microsoft.Store.PartnerCenter.AuthenticationToken], [System.Management.Automation.PowerShell]
    Add-Type -ReferencedAssemblies ($ExtraAssemblies.Assembly.Location + $RefAssemblies) -TypeDefinition @'
using System;
using System.Threading.Tasks;
using System.Management.Automation;
using System.Management.Automation.Host;
using Microsoft.Store.PartnerCenter;

namespace DelegateHelper
{
    public class ScriptBlockDelegate
    {
        public PSHost Host { get; set; }
        public ScriptBlock Code { get; set; }
        public PSCredential Credential { get; set; }
        public String RefreshToken { get; set; }
        public String Tenant { get; set; }
        public ScriptBlock Function { get; set; }

        public ScriptBlockDelegate(PSHost host, ScriptBlock code, PSCredential credential, String refreshToken, String tenant, ScriptBlock function)
        {
            Host = host;
            Code = code;
            Credential = credential;
            RefreshToken = refreshToken;
            Tenant = tenant;
            Function = function;
        }
        public Task<AuthenticationToken> Delegate(AuthenticationToken expiredAuthenticationToken)
        {
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddScript(Code.ToString());
                ps.AddArgument(expiredAuthenticationToken).AddArgument(Credential).AddArgument(RefreshToken).AddArgument(Tenant).AddArgument(Function);
                AuthenticationToken newAuthenticationToken = ps.Invoke<AuthenticationToken>(
                    null,
                    new PSInvocationSettings()
                    {
                        Host = Host,
                    }
                )[0];
                return Task<AuthenticationToken>.Run(() =>
                {
                    return newAuthenticationToken;
                });
            }
        }
    }
}
'@
    $Callback = {
        param (
            [Microsoft.Store.PartnerCenter.AuthenticationToken]$ExpiredAuthenticationToken,

            [Parameter(Mandatory)]
            [PSCredential]$Credential,

            [Parameter(Mandatory)]
            [String]$RefreshToken,

            [string]$Tenant,

            [Parameter(Mandatory)]
            [ScriptBlock]$Function
        )
        $AccessToken = $Function.Invoke($Credential, $RefreshToken, $Tenant)
        [Microsoft.Store.PartnerCenter.AuthenticationToken]::new($AccessToken[0], $AccessToken[1])
    }
    $Delegate = [DelegateHelper.ScriptBlockDelegate]::new($host, $Callback, $Credential, $RefreshToken, $Tenant, ${function:New-PartnerAccessToken})
    $TokenRefresher = $Delegate.Delegate

    $PartnerCredentials = [Microsoft.Store.PartnerCenter.Extensions.PartnerCredentials]::Instance.GenerateByUserCredentials(
        $ApplicationId,
        [Microsoft.Store.PartnerCenter.AuthenticationToken]::new($AccessToken[0], $AccessToken[1]),
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

        # Reseller tenant ID, if not provided filter customers from specific reseller.
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