# PowerShell Helper for Microsoft Graph API 

## **App Registration & Configuration**
https://docs.microsoft.com/en-us/graph/auth-register-app-v2

1. Provide a name for the application. I used **GraphAPIApp**.
2. "**Supported account types**", set this to "**Accounts in this organizational directory only (brandev-rpio only - Single tenant)**" and click "**Register**". You will be redirected to the app configuration page.
3. Under the "**Overview**" section of the app, copy the "**Application (client) ID**" and save it somewhere for later use.
4. Click on "**Authentication**" and under the "**Suggested Redirect URIs for public clients (mobile, desktop)**" select the checkbox next to https://login.microsoftonline.com/common/oauth2/nativeclient and click "**Save**".
5. Move to "**API permissions**" and select "**Add a permissions**" and click on "**Microsoft Graph**" then choose "**Application permissions**".
6. Select "**Mail Read**" and click "**Add permissions**".
7. Finally, under "**Grant consent**", click "**Grant admin consent for contoso**" and click "**Yes**" to the prompt.
8. To allow the PowerShell client to authenticate without a user present, we will use a client certificate. Using PowerShell, run the following and be sure to change the following.

   - **`<FriendlyName>`** to something like "**GraphAPI Client Cert**". 
   - **`<KeyDescription>`** to something like "**Used to access Microsoft Graph API**".
   - **`<Subject>`** to your domain name, i.e., "**contoso.com**".

 ```powershell
  $cert = New-SelfSignedCertificate `
         -CertStoreLocation cert:\currentuser\my `
         -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
         -KeyUsage DigitalSignature,DataEncipherment,KeyEncipherment `
         -KeyAlgorithm RSA `
         -KeyLength 2048 `
         -Subject <Subject> `
         -FriendlyName <FriendlyName> `
         -KeyDescription <KeyDescription> `
         -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddYears(2);
 ```  
 
9. Copy and save the thumbprint for later use.

```powershell
 $cert.Thumbprint | clip
 ```

10. Export the certificate and upload it to the app using the "**Upload certificate**" button from the "**Certificates & secrets**" page.

```powershell
 Export-Certificate -Type CERT -Cert $cert -FilePath c:\temp\graphapi.cer;
 ```
More details on using certificates can be found here: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials. 


## **Usage**
Download the repository and . source the POSHGraphHelpers.ps1 file.
```powershell
. c:\temp\POSHGraphHelpers.ps1
```

**Using PowerShell, create some variables.**
The **$ClientId** and the **$Thumbprint** should be set to the "**Application (client) ID**" and **Thumprint** you copied and saved earlier.

```powershell
$TenantName = 'contoso.onmicrosoft.com'
$ClientId = "49e13ad6-bb04-499b-b96b-90fc7858be54"
$Thumbprint = 'EC7FC6004A651EE8BECF269A7A86163771C6C562'
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

## **More samples to come...**
