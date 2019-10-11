# PowerShell Helper for Microsoft Graph API 

## **Setup**
#### App Registration
https://docs.microsoft.com/en-us/graph/auth-register-app-v2

```powershell
Coming soon...
```

#### Create a self-signed client certificate
Create a self-signed client certificate and upload it to the App Registration. 
https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials

```powershell
New-GraphAPICertificate -Subject contoso.com -FriendlyName "Graph API Client Cert" -Description "Used to access Graph API" -ExportLocation "c:\temp\"
```



## **Usage**
Download the repository and . source the POSHGraphHelpers.ps1 file.
```powershell
. c:\temp\POSHGraphHelpers.ps1
```

**Create some variables.**
```powershell
$TenantName = 'contoso.onmicrosoft.com'
$ClientId = "49e13ad6-bb04-499b-b96b-90fc7858be54"
$Thumbprint = 'EC7FC6004A651EE8BECF269A7A86163771C6C562'
$ClientSecret = 'o:KhJyp5bvWq4[aDb=0K]5]ZbjsVV3o@'
```

**Connect to Microsoft Graph API**
```powershell
$AccessToken = $null
$AccessToken = Get-AccessToken -TenantName $TenantName -ClientId $ClientId -CertificateThumbprint $Thumbprint
```

**Use the API by passing the Invoke-GraphQuery function a URL.**
```powershell
$uri = "https://graph.microsoft.com/v1.0/users/John@contoso.com"
Invoke-GraphQuery -AccessToken $AccessToken -Uri $uri

Method: GET | URI https://graph.microsoft.com/v1.0/users/John@contoso.com | Found: 1


@odata.context    : https://graph.microsoft.com/v1.0/$metadata#users/$entity
businessPhones    : {}
displayName       : John
givenName         : John
jobTitle          :
mail              : John@contoso.com
mobilePhone       :
officeLocation    :
preferredLanguage :
surname           :
userPrincipalName : John@contoso.com
id                : 48d9c121-bb2c-402b-bedf-612296500d2e
```


