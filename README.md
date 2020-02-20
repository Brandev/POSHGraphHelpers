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
Using the Microsoft Graph PowerShell SDK 

https://github.com/microsoftgraph/msgraph-sdk-powershell

</br>

1. First, install the module.

    ```powershell
    if(!(Get-PSRepository GraphPowerShell -ErrorAction:SilentlyContinue)){
        Register-PSRepository -Name GraphPowerShell -SourceLocation 'https://graphpowershellrepository.azurewebsites.net/nuget' -InstallationPolicy Trusted
    }
    
    if(!(Get-Module GraphPowerShell -ListAvailable -ErrorAction:SilentlyContinue)){
        Install-module Microsoft.Graph.Beta -Repository GraphPowerShell
    }
    ```
</br>

2. Next, you can use either a json config file or a configuration object to host the TenantId, ClientId and Certificate Thumbprint.

    a. If using a json config file...
    
    ```powershell
    $config = Get-Content .\config\clientconfiguration.json -Raw | ConvertFrom-Json
    ```
    
    b. If using an object...
    ```powershell
    $config = [PSCustomObject]@{
        TenantId = 'ae5a8e02-eac1-4e89-8991-f446d532347f'
        ClientId = '49a4017d-87d6-4fc9-9e5c-63091de4838f'
        Thumbprint = '67F597273BB23D345987D1B1F5D79682B1DA2C2B'
    }
    ```
</br>

3. Connect
    ```powershell
    Connect-Graph -ClientId $config.ClientId -TenantId $config.TenantId -CertificateThumbprint $config.Thumbprint
    ```
</br>

4. Verify
    ```powershell
    Get-User -UserId brandon@contoso.com
    ```
