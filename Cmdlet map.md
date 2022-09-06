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

### New-PartnerAccessToken (Refresh token to access token)
``` pwsh
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

### New-PartnerRefreshToken (`New-PartnerAccessToken` web app to Refresh token)
``` pwsh
# Old
$Token = New-PartnerAccessToken -ApplicationId <String> -Scopes 'https://api.partnercenter.microsoft.com/user_impersonation' [-Tenant <String>] -UseDeviceAuthentication
# New
$Token = New-PartnerRefreshToken -ApplicationId <String> [-Scopes <String<>>] [-Tenant <String>] -AuthenticationFlow DeviceCode
```
| Param                   | Status                                              |
| ----------------------- | --------------------------------------------------- |
| Credential              | ❌                                                  |
| RefreshToken            | ❌                                                  |
| Tenant                  | ✔️                                                |
| AccessToken             | ❌                                                  |
| ApplicationId           | ✔️                                                |
| CertificateThumbprint   | ❌                                                  |
| Environment             | ❌                                                  |
| Module                  | ❌                                                  |
| Scopes                  | ✔️ Optional.                                      |
| ServicePrincipal        | ❌                                                  |
| UseAuthorizationCode    | ❌ will be replaced by  `-AuthenticationFlow OIDC`. |
| UseDeviceAuthentication | ❌ replaced by `-AuthenticationFlow DeviceCode`.    |
| AuthenticationFlow      | 🆕                                                  |
| OutputFormat            | 🆕                                                  |