# PowerShell Helper for Micrsoft Graph API 


#### App Registration
https://docs.microsoft.com/en-us/graph/auth-register-app-v2
</br></br>

#### To Create a self-signed client certificate for authentication. Upload the certificate to the App Registration
New-GraphAPICertificate -Subject contoso.com -FriendlyName "Graph API Client Cert" -Description "Used to access Graph API" -ExportLocation "c:\temp\"

Ref: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
