# Changelog
**Note: Project is still WIP, any update can contain braking changes**

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.3-alpha] - 2022-09-13
### Added
* `Get-PartnerCustomerOrder`.
* Added new transition CmdLets to NCE `Get-TransitionEligibilities` and `New-Transition`.
* `-OutputFormat` added to CmdLets with new `FlatAutoFull`, `FlatAutoNoLinksAttributes` and example of `Compatibility`.
### Packaging
* Add missing dependency `[Microsoft.IdentityModel.Abstractions]`.
* `Microsoft.Identity.Client.dll` load implicitly if needed as a dependency.
* Dll updater helper `Updater.ps1`.
* Update dlls:
    ```log
    Name                                         Existing New
    ----                                         -------- ---
    Microsoft.IdentityModel.Abstractions.dll              6.23.0.30906
    Microsoft.Identity.Client.dll                4.46.1.0 4.46.2.0
    Microsoft.Store.PartnerCenter.dll            3.1.2    3.1.2
    Microsoft.Store.PartnerCenter.Extensions.dll 3.1.2    3.1.2
    Microsoft.Store.PartnerCenter.Models.dll     3.1.2    3.1.2
    ```

## [0.0.2-alpha] - 2022-09-08
### Added
* `Connect-PartnerCenter -RefreshTokenScript`.
* `New-PartnerWebApp -AuthenticationFlowAllowed`.
* `New-PartnerRefreshToken -AuthenticationFlow OIDC` With [Pode](https://badgerati.github.io/Pode/).

## [0.0.1-alpha] - 2022-09-05
* Release Test.

## [0.0.0] - 2022-09-05
### Added
* `New-PartnerWebApp`.
* `Examples\Authentication.ps1`.
* `New-PartnerAccessToken`, `New-PartnerRefreshToken`, `New-PartnerWebApp` OutputFormat.

## [0.0.0] - 2022-08-31
### Added
* `New-PartnerRefreshToken` contributed by [@koenhalfwerk](https://github.com/koenhalfwerk) pull https://github.com/ili101/PartnerCustomerCommunity/pull/2.

## [0.0.0] - 2022-08-30
### Added
* "TokenRefresher" using [PSRunspacedDelegate](https://www.powershellgallery.com/packages/PSRunspacedDelegate/0.1).

## [0.0.0] - 2022-08-10
### Added
* [Cmdlet map.md](Cmdlet%20map.md).

## [0.0.0] - 2022-06-22
* First commit.