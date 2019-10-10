# PowerShell Helper for Micrsoft Graph API 


#### App Registration
https://docs.microsoft.com/en-us/graph/auth-register-app-v2
</br></br>

#### To Create a self-signed client certificate for authentication. Upload the certificate to the App Registration
1. Create Certificate saved to private store. 

New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -KeyUsage DigitalSignature,DataEncipherment,KeyEncipherment `
-KeyAlgorithm RSA -KeyLength 2048 -Subject "cn=contoso.com" `
-FriendlyName "GraphAPI Client Cert" `
-KeyDescription "Used to access GraphAPI" -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddYears(2);

2. Fetch cert from store and save public key to folder for uploading to App. 

$cert = Get-ChildItem Cert:\CurrentUser\my | ?{$_.Thumbprint -eq 'EC7FC6004A651EE8BECF269A7A86163771C6C562'}
Export-Certificate -Type CERT -Cert $cert -FilePath 'c:\temp\graphapi.cer'
</br></br>

Ref: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
