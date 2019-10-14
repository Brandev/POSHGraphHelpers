# PowerShell Helper for Microsoft Graph API 

## **App Registration & Azure Configuration**

1. Provide a name for the application. I used "**GraphAPIApp**".
2. "**Supported account types**", set this to "**Accounts in this organizational directory only (contoso only - Single tenant)**" and click "**Register**". You will be redirected to the app configuration page.
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
</br>

More details on using certificates can be found here: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials.

More details on the App Registration process can be found here: https://docs.microsoft.com/en-us/graph/auth-register-app-v2
</br>

## **Usage**
**Client Setup**
1. Download the repository then extract the "**POSHGraphHelpers.ps1**" and "**POSHGraphHelpersConfig.json**" files to your working directory.
2. Edit the "**POSHGraphHelpersConfig.json**" file and set the values accordingly. Note the "**ClientId**" is the "**Application (client) ID**" you copied earlier. The "**Thumbprint**" is the **Thumprint** you copied and saved earlier.
3. Finally, . source the "**POSHGraphHelpers.ps1**" file.

```powershell
. c:\temp\POSHGraphHelpers.ps1
```
</br>

**Connect to Microsoft Graph API**
```powershell
Get-AccessToken -Certificate

Success!

Use the $GraphAPIAccessToken variable to view the access token details.

```
</br>

**Use the API by passing the Invoke-GraphQuery function a URL.**
```powershell
$uri = "https://graph.microsoft.com/v1.0/users/John@contoso.com"
Invoke-GraphQuery -Uri $uri

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