# PartnerCustomerCommunity
This is an open source Powershell module for Microsoft Partner Center.

## Motivation
The official Microsoft module https://github.com/microsoft/PartnerCenterPowerShellModule was deprecated.</br>
The replacement "unofficial" Microsoft module https://github.com/microsoft/Partner-Center-PowerShell seems to be [abandoned](https://github.com/microsoft/Partner-Center-PowerShell/issues/396).

## Goal
An alternative module made by and for the Powershell community.</br>
Make it easy and inviting to anyone that wants to contribute by fixing or adding functionality using Powershell.

## Improvements over PartnerCustomer so far
* Uses the latest version of the dlls. Probably solves some of the open PartnerCustomer module Issues? if you know of something specific please share.
* Now parameter `Get-PartnerCustomer -IndirectResellerId <GUID>`.
* Get Cmdlets output usually have more data.
* Optional async support to support faster parallel execution.
* New CmdLet `New-PartnerWebApp`.
* Now parameter `Connect-PartnerCenter -RefreshTokenScript <ScriptBlock>`.
* New CmdLets for NCE transition: `Get-TransitionEligibilities` and `New-Transition`.

## Design choices
#### Language
We have 3 ways going about this:
|                          | Advantages                                                     | Disadvantages                                            |
| ------------------------ | -------------------------------------------------------------- | -------------------------------------------------------- |
| Fork the MS project (C#) | It already exists, just need to update and maintain it.        | Need people that know and want to maintain a C# project. |
| PowerShell using dlls    | Can be maintained and contributed by anyone with PS knowledge. | Also need basic classes usage knowledge in PS.           |
| PowerShell using REST    | Can be maintained and contributed by anyone with PS knowledge. | Need to manually handle the API with its oddities.       |

I think that we should go with the PowerShell + dlls approach, it requires only Powershell knowledge to contribute. We can potentially fall back to REST if we find blockers working with the dlls.

#### Cmdlets
* We can maintain the same Cmdlets and parameters names as [PartnerCenter](https://www.powershellgallery.com/packages/PartnerCenter/) when reasonable. This make the module easy to migrate to and also make it easier to write as we have a good baseline to work on and existing documentation.
* We can potentially add multiple options to the new `-OutputFormat` parameter on all Cmdlets. with option like "Raw" (return all as is), "Compatibility" (equivalent to PartnerCenter), "New", etc.

## Cmdlets implemented so far
* `New-PartnerWebApp` 🆕
* `New-PartnerRefreshToken` 🔃
* `New-PartnerAccessToken`
* `Connect-PartnerCenter`
* `Get-PartnerOrganizationProfile`
* `Get-PartnerCustomer`
* `Get-PartnerCustomerSubscription`
* `Get-PartnerIndirectReseller`
* `Get-PartnerCustomerOrder`
* `Get-TransitionEligibilities` 🆕
* `New-Transition` 🆕

More info [Cmdlet map.md](Cmdlet%20map.md)

#### The following Cmdlets will probably be unexposed later
Rest example Cmdlets:
* `Get-PartnerCustomerRestExample` - Rest implementation example.
* `Get-PartnerOrganizationProfileRestExample` - Rest implementation example.

## Authentication
Implements the authentication flow https://docs.microsoft.com/en-us/partner-center/develop/enable-secure-app-model

### General steps
#### Create a web app (admin user -> web app)
New CmdLet using [Microsoft.Graph](https://github.com/microsoftgraph/msgraph-sdk-powershell) `New-PartnerWebApp`.
#### Get an authorization code (web app -> authorization code)
#### Get a refresh token (authorization code -> refresh token)
To achieve those 2 steps you can run `New-PartnerRefreshToken`.
#### Get an access token (refresh token -> access token).
Connecting will do this automatically `Connect-PartnerCenter`.
#### Make a Partner Center API call
Just run any of the CmdLets, `Connect-PartnerCenter` holds the session credentials in the module scope.

### Example
Example [Examples/Authentication.ps1](Examples/Authentication.ps1)

## ToDo
Help appreciated, open an issue to collaborate🙏
#### Prioritized
* ~~Find how to refresh the token, currently it will expire after 1 hours and it's needed to run `Connect-PartnerCenter` again.~~
* Implement more Cmdlets from the PartnerCenter module.
* Probably more stuff im missing 😅.
#### Optional
* Add more `-OutputFormat` parameter options to Cmdlets.
* ~~Add App creation if there is interest? (code exist but need to be updated and cleaned as it uses deprecated MS modules).~~
* ~~Add `New-PartnerRefreshToken -AuthenticationFlow 'OIDC'` using "Pode".~~
* Add GitHub Actions testing. We will probably need a "Demo" PartnerCustomer organization for this?
* Organizing the module better, for example separate functions to different files and so.
* Documentation.
* Add usage examples for common scenarios or even new Cmdlets.

## How to contribute
Open an Issue or make a Pull request.</br>
To add Cmdlets copy one of the existing ones and edit as needed, there are examples on the microsoft site.
For example taking this C# example https://docs.microsoft.com/en-us/partner-center/develop/get-an-organization-profile#c and converting it to Powershell:</br>
**C#**
```CSharp
OrganizationProfile organizationProfile = partnerOperations.Profiles.OrganizationProfile.Get();
```
**Powershell**
```pwsh
$organizationProfile = $PartnerOperations.Profiles.OrganizationProfile.Get()
```

## Troubleshooting
Q: When trying to `Import-Module` you get the error "Add-Type: Assembly with same name is already loaded".</br>
A: The old PartnerCustomer module is imported in your PS sassoon, the 2 module cannot be imported as PS cannot load 2 different versions of the same dlls.
Note that if you use VSCode it may import the old module implicitly, to prevent this remove the old module from your module folder and import it manually from another folder if needed.