function New-GraphAPICertificate {
  <#
	.SYNOPSIS
    Create a new self-signed certificate used to authenticate against Azure AD.    
    
    .DESCRIPTION
    Certificate will be located in the user certificate store.

    .PARAMETER Subject
    The Domain name. i.e., contoso.com

    .PARAMETER FriendlyName
    The Friendly name. i.e., 'GraphAPI Client Cert'

    .PARAMETER Description
    The Description. i.e., 'Used to access GraphAPI'

    .PARAMETER ExportLocation
    Path where you want to export the certificate to. i.e., 'C:\temp'

    .EXAMPLE
    New-GraphAPICertificate -Subject contoso.com -FriendlyName "Graph API Client Cert" -Description "Used to access Graph API" -ExportLocation "c:\temp\"
    #>
    
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Domain name. i.e., contoso.com")]
        [ValidateNotNullorEmpty()]
        $Subject,
        
        [Parameter(Mandatory = $true, HelpMessage = "i.e., 'GraphAPI Client Cert'")]
        [ValidateNotNullorEmpty()]
        $FriendlyName,

        [Parameter(Mandatory = $true, HelpMessage = "i.e., 'Used to access GraphAPI'")]
        [ValidateNotNullorEmpty()]
        $Description,

        [Parameter(Mandatory = $true, HelpMessage = "Path where you want to export the certificate to. i.e., 'C:\temp'")]
        [ValidateNotNullorEmpty()]
        $ExportLocation
    )
    try {
        $cn = 'cn=' + $Subject;
        $cert = New-SelfSignedCertificate `
        -CertStoreLocation cert:\currentuser\my `
        -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -KeyUsage DigitalSignature,DataEncipherment,KeyEncipherment `
        -KeyAlgorithm RSA `
        -KeyLength 2048 `
        -Subject $cn `
        -FriendlyName $FriendlyName `
        -KeyDescription $Description `
        -NotBefore (Get-Date).AddDays(-1) -NotAfter (Get-Date).AddYears(2);

        if(!(Test-Path $ExportLocation)){
            throw "Export location does not exist."
        }
        $ExportLocation = $ExportLocation.TrimEnd('\\') + '\graphapi.cer'
        Export-Certificate -Type CERT -Cert $cert -FilePath $ExportLocation;
    }
    catch {
        Write-Error $_.Exception
    }
}
function Get-ClientCertificate {
    <#
	.SYNOPSIS
    Retreives a client certificate from the user certificate store that can be used to authenticate against Azure AD.
	
    .PARAMETER Thumbprint
    The client certificate thumbprint of the certificate.
    
    .EXAMPLE
    $Certificate = Get-ClientCertificate -Thumbprint 'EC7FC6004A651EE8BECF269A7A86163771C6C562';
    #>
    [CmdletBinding(DefaultParameterSetName = 'Thumbprint')]
    param
    (
        [Parameter(ParameterSetName = 'Thumbprint', Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Thumbprint
    )
    $results = Get-ChildItem Cert:\CurrentUser\my | ? { $_.Thumbprint -eq $Thumbprint }; 
    return $results
}
function Set-Deps {
    <#
	.SYNOPSIS
    Load the Active Directory Authentication Library (ADAL) to allow for authenticatication against Azure AD.    
    #>
    try {
        $AadModule = Get-Module -Name "AzureAD*" -ListAvailable -ErrorAction:SilentlyContinue;
        if (!$AadModule) {
            { Install-Module AzureAD }
            $AadModule = Get-Module -Name "AzureAD*" -ListAvailable -ErrorAction:SilentlyContinue;
        }
    
        if ($AadModule.count -gt 1) {
            $Latest_Version = ($AadModule | select version | Sort-Object)[-1]
            $AadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }      
        }
        $AadModuleLib = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll";
        Import-Module $AadModuleLib;
        return $true;
    }
    catch {
        return $false;
    }
  
}
function Get-AccessToken {
    <#
	.SYNOPSIS
    Uses the Active Directory Authentication Library (ADAL) to authenticate against Azure AD.    
	
    .PARAMETER TenantName
    The name of the tenant. i.e., contoso.onmicrosoft.com or contoso.com

    .PARAMETER ClientId
    The ClientId of the app registered in Azure AD.

    .PARAMETER ClientSecret
    The client secret for the app registered in Azure AD.

    .PARAMETER CertificateThumbprint
    The client certificate thumbprint of the app registered in Azure AD.

    .EXAMPLE
    $AccessToken = Get-AccessToken -Tenant $TenantName -ClientId $ClientId -ClientSecret 'qkDwDJlDfig2IpeuUZYKH1Wb8q1V0ju6sILxQQqhJ+s'
    $AccessToken = Get-AccessToken -Tenant $TenantName -ClientId $ClientId -Certificate 'EC7FC6004A651EE8BECF269A7A86163771C6C562'
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "ClientSecret")]
        [Parameter(Mandatory = $true, ParameterSetName = "CertificateThumbprint")]
        [string]$TenantName,
        
        [Parameter(Mandatory = $true, ParameterSetName = "ClientSecret")]
        [Parameter(Mandatory = $true, ParameterSetName = "CertificateThumbprint")]
        [System.Guid]$ClientID,

        [Parameter(Mandatory = $true, ParameterSetName = "ClientSecret")]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "CertificateThumbprint")]
        [string]$CertificateThumbprint
    )
    
    try {

        if (!(Set-Deps)) {
            throw "Unable to load authentication libraries."
        }

        $resourceAppIdURI = "https://graph.microsoft.com";
 
        $authority = " https://login.microsoftonline.com/$TenantName/oauth2/token";      

        $clientCredential = $null;

        $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($authority);
        
        $authResult = $null;

        switch ($PSCmdlet.ParameterSetName) {
            "CertificateThumbprint" {
                $Certificate = Get-ClientCertificate -Thumbprint $CertificateThumbprint;
                $clientCredential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate($ClientId, $Certificate); 
                $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientcredential).Result;

                return $authResult
            }
            "ClientSecret" {
                $clientCredential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($ClientId, $ClientSecret); 
                $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientcredential).Result;
            }
        }

        return $authResult
    }
    catch {
        Write-Error $_.Exception
    }
}
function Invoke-GraphQuery {
    <#
	.SYNOPSIS
    Helper function to make API calls against Microsoft Graph API.
	
    .PARAMETER AccessToken
    The AccessToken aquired when authenticated using the Get-AccessToken function.

    .PARAMETER URI
    The API URL.

    .PARAMETER METHOD
    The HTTP verb type. Currently only GET is supported.

    .EXAMPLE
    $uri = "https://graph.microsoft.com/beta/reports/getEmailActivityUserDetail(period='D7')?`$format=application/json"
    $activity = Invoke-GraphQuery -AccessToken $AccessToken -Uri $uri 
    $activity
    #>
    param
    (          
        [Parameter(Mandatory = $true)]
        $AccessToken,
        [Parameter(Mandatory = $true)]
        $URI,
        [Parameter(Mandatory = $false)]
        $Method = "GET"
    )
        
    Write-Progress -Id 1 -Activity "Executing query: $uri" -CurrentOperation "Invoking MS Graph API";

    $Header = @{ 'Content-Type' = 'application\json'; 'Authorization' = $AccessToken.CreateAuthorizationHeader() }

    $QueryResults = @()
    if ($Method -eq "Get") {
        do {
            $Results = Invoke-RestMethod -Headers $Header -Uri $uri -UseBasicParsing -Method $Method -ContentType "application/json"
            if ($null -ne ($Results.value)) { $QueryResults += $Results.value }
            else { $QueryResults += $Results }
            write-host "Method: $Method | URI $Uri | Found:" ($QueryResults).Count
            $uri = $Results.'@odata.nextlink'
        }until (!($uri))
    }
   
    Write-Progress -Id 1 -Activity "Executing query: $Uri" -Completed
    Return $QueryResults
}
