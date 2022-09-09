❌ Exist in old module but not on `PartnerCustomerCommunity` (unneeded, replaced or not implemented yet).<br>
✔️ Exist in both modules.<br>
🆕 New parameter/functionality in `PartnerCustomerCommunity` that was not in old module.<br>
🔃 New replacement/renamed.

### 🆕 New-PartnerWebApp
Converted from CyberDrain new application script:
https://www.cyberdrain.com/connect-to-exchange-online-automated-when-mfa-is-enabled-using-the-secureapp-model
| Param                     | Status                  |
| ------------------------- | ----------------------- |
| DisplayName               | ✔️                    |
| TenantId                  | ❌ Renamed to `-Tenant` |
| Tenant                    | 🔃                     |
| DisplayName               | 🆕                      |
| AuthenticationFlow        | 🆕                      |
| AuthenticationFlowAllowed | 🆕                      |
| StayConnected             | 🆕                      |
| OutputFormat              | 🆕                      |

### 🔃 New-PartnerRefreshToken (`New-PartnerAccessToken` web app to Refresh token)
``` powershell
# Old AuthenticationFlow DeviceCode:
$Token = New-PartnerAccessToken -ApplicationId <String> -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' [-Tenant <String>] -UseDeviceAuthentication
# New AuthenticationFlow DeviceCode:
$Token = New-PartnerRefreshToken -ApplicationId <String> [-Scopes <String<>>] [-Tenant <String>] -AuthenticationFlow DeviceCode

# Old AuthenticationFlow OIDC:
$Token = New-PartnerAccessToken -Credential <App PSCredential> -Tenant <String> -ApplicationId <String> -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' -ServicePrincipal -UseAuthorizationCode
# New AuthenticationFlow OIDC:
$Token = New-PartnerRefreshToken -Credential <App PSCredential> [-Tenant <String>] [-Scopes <String<>>]
```
| Param                   | Status                                             |
| ----------------------- | -------------------------------------------------- |
| Credential              | ✔️ ParameterSet `-AuthenticationFlow OIDC`.       |
| RefreshToken            | ❌                                                 |
| Tenant                  | ✔️ Optional.                                     |
| AccessToken             | ❌                                                 |
| ApplicationId           | ✔️ ParameterSet `-AuthenticationFlow DeviceCode`. |
| CertificateThumbprint   | ❌                                                 |
| Environment             | ❌                                                 |
| Module                  | ❌                                                 |
| Scopes                  | ✔️ Optional.                                     |
| ServicePrincipal        | ❌                                                 |
| UseAuthorizationCode    | ❌ Replaced by  `-AuthenticationFlow OIDC`.        |
| UseDeviceAuthentication | ❌ Replaced by `-AuthenticationFlow DeviceCode`.   |
| AuthenticationFlow      | 🔃 Default: OIDC.                                  |
| OutputFormat            | 🆕                                                 |

### New-PartnerAccessToken (Refresh token to access token)
``` powershell
# Old
New-PartnerAccessToken -Credential <App PSCredential> -RefreshToken <String> [-Tenant <String>] -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation'
# New
New-PartnerAccessToken -Credential <App PSCredential> -RefreshToken <String> [-Tenant <String>]
```
| Param                   | Status |
| ----------------------- | ------ |
| Credential              | ✔️   |
| RefreshToken            | ✔️   |
| Tenant                  | ✔️   |
| AccessToken             | ❌     |
| ApplicationId           | ❌     |
| CertificateThumbprint   | ❌     |
| Environment             | ❌     |
| Module                  | ❌     |
| Scopes                  | ❌     |
| ServicePrincipal        | ❌     |
| UseAuthorizationCode    | ❌     |
| UseDeviceAuthentication | ❌     |
| OutputFormat            | 🆕     |

### Connect-PartnerCenter
Currently only support [App + User authentication](https://docs.microsoft.com/en-us/partner-center/develop/partner-center-authentication#app--user-authentication) (not sure if other methods are needed or still supported?).
| Param                 | Status                                                       |
| --------------------- | ------------------------------------------------------------ |
| Credential            | ✔️                                                         |
| RefreshToken          | ✔️                                                         |
| Tenant                | ✔️                                                         |
| AccessToken           | ❌                                                           |
| ApplicationId         | ❌ Why is it needed? We have this in `-Credential` UserName. |
| CertificateThumbprint | ❌                                                           |
| Environment           | ❌                                                           |
| ServicePrincipal      | ❌                                                           |
| RefreshTokenScript    | 🆕 For saving the now generated extended "refresh token".     |

### Get-PartnerOrganizationProfile
| Param             | Status |
| ----------------- | ------ |
| Async             | 🆕⚙️ |
| PartnerOperations | 🆕⚙️ |

### Get-PartnerCustomer
| Param              | Status                                                                      |
| ------------------ | --------------------------------------------------------------------------- |
| CustomerId         | ✔️                                                                        |
| InputObject        | 🆕 Pipeline Customer.                                                       |
| IndirectResellerId | 🆕 Reseller tenant ID, if provided filter customers from specific reseller. |
| Async              | 🆕⚙️                                                                      |
| PartnerOperations  | 🆕⚙️                                                                      |
| Domain             | ❌                                                                          |

### Get-PartnerCustomerSubscription
| Param             | Status |
| ----------------- | ------ |
| InputObject       | ✔️   |
| CustomerId        | ✔️   |
| Async             | 🆕⚙️ |
| PartnerOperations | 🆕⚙️ |
| OrderId           | ❌     |
| MpnId             | ❌     |
| SubscriptionId    | ❌     |

### Get-PartnerIndirectReseller
| Param             | Status                |
| ----------------- | --------------------- |
| CustomerId        | ✔️                  |
| InputObject       | 🆕 Pipeline Customer. |
| Async             | 🆕⚙️                |
| PartnerOperations | 🆕⚙️                |
