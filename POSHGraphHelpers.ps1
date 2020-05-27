function Get-ClientCertificate {
    <#
	.SYNOPSIS
    Retreives a client certificate from the user certificate store that can be used to authenticate against Azure AD.
    Ensure the thumbprint for the certificate is set in the config file.

    .EXAMPLE
    $Certificate = Get-ClientCertificate;
    #>
    $results = Get-ChildItem Cert:\CurrentUser\my | Where-Object { $_.Thumbprint -eq $script:GraphAPICerThumbprint }; 
    return $results
}
function Set-Deps {
    <#
	.SYNOPSIS
    Load the Active Directory Authentication Library (ADAL) to allow for authenticatication against Azure AD.  
    Validate the configuration file is populated and loaded  
    #>
    try {
        $isValid = $false;
        $AadModule = Get-Module -Name "AzureAD*" -ListAvailable -ErrorAction:SilentlyContinue;
        if (!$AadModule) {
            { Install-Module AzureAD }
            $AadModule = Get-Module -Name "AzureAD*" -ListAvailable -ErrorAction:SilentlyContinue;
        }
    
        if ($AadModule.count -gt 1) {
            $Latest_Version = ($AadModule | Select-Object version | Sort-Object)[-1]
            $AadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }      
        }
        $AadModuleLib = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll";
        Import-Module $AadModuleLib;

        $config = Get-Content .\POSHGraphHelpersConfig.json | ConvertFrom-Json;
        $script:GraphAPITenant = $config.TenantName;
        $script:GraphAPIClientId = $config.ClientId;
        $script:GraphAPIClientSecret = $config.ClientSecret;
        $script:GraphAPICerThumbprint =  $config.Thumbprint;

        $isValid = (
            ($script:GraphAPITenant.Length -gt 10) -or `
            ($script:GraphAPIClientId.Length -gt 10) -or `
            ($script:GraphAPIClientSecret.Length -gt 10) -or `
            ($script:GraphAPICerThumbprint.Length -gt 10)           
            )

        return $isValid;
    }
    catch {
        return $false;
    }
  
}
function Get-AccessToken {
    <#
	.SYNOPSIS
    Uses the Active Directory Authentication Library (ADAL) to authenticate against Azure AD.    

    .PARAMETER ClientSecret
    Switch to indicate the use of the client secret, set in the config file, to authenticate.

    .PARAMETER Certificate
    Switch to indicate the use of the client certificate, located in the user certificate store to authenticate. 
    Ensure the thumbprint for the certificate is set in the config file.

    .EXAMPLE
    Get-AccessToken -ClientSecret
    Get-AccessToken -Certificate
    $GraphAPIAccessToken
    #>
    [CmdletBinding(DefaultParameterSetName = "Certificate")]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = "ClientSecret")]
        [switch]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "Certificate")]
        [switch]$Certificate
    )
    try {
        if (!(Set-Deps)) {
            throw "Unable to load authentication libraries."
        }
        $resourceAppIdURI = "https://graph.microsoft.com";
 
        $authority = " https://login.microsoftonline.com/$GraphAPITenant/oauth2/token";      

        $clientCredential = $null;

        $authContext = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext($authority);
        
        $authContext.TokenCache.Clear();

        $script:GraphAPIAccessToken = $null;

        switch ($PSCmdlet.ParameterSetName) {
            "Certificate" {
                $ClientCertificate = Get-ClientCertificate -Thumbprint $script:GraphAPICerThumbprint;
                $clientCredential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate($script:GraphAPIClientId, $ClientCertificate); 
                $response = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientcredential).GetAwaiter().GetResult();
               
				if($response.IsFaulted){
                    $e = [System.Exception]::new($response.Exception);
                    throw $e;
                }
                $script:GraphAPIAccessToken = $response;
            }
            "ClientSecret" {
                $clientCredential = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential($script:GraphAPIClientId, $script:GraphAPIClientSecret); 
                $response = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientcredential).GetAwaiter().GetResult();

                if($response.IsFaulted){
                    $e = [System.Exception]::new($response.Exception)
                    throw $e.ToString();
                }
                $script:GraphAPIAccessToken = $response;
            }
        }

       Write-Host "`r`nSuccess!`r`n" -ForegroundColor Green;
       Write-Host "Use the " -NoNewline;
       Write-Host "`$GraphAPIAccessToken " -ForegroundColor Cyan -NoNewline;
       Write-Host "variable to view the access token details.`r`n"
    }
    catch {
        Write-Error $_
    }
}
function Invoke-GraphQuery {
    <#
	.SYNOPSIS
    Helper function to make API calls against Microsoft Graph API.

    .PARAMETER URI
    The API URL.

    .PARAMETER METHOD
    The HTTP verb type. Currently only GET is supported.

    .EXAMPLE
    $uri = "https://graph.microsoft.com/beta/reports/getEmailActivityUserDetail(period='D7')?`$format=application/json"
    $activity = Invoke-GraphQuery -Uri $uri 
    $activity
    #>
    param
    (
        [Parameter(Mandatory = $true)]
        $URI,
        [Parameter(Mandatory = $false)]
        $Method = "GET"
    )
        
 try {
    Write-Progress -Id 1 -Activity "Executing query: $uri" -CurrentOperation "Invoking MS Graph API";

    $Header = @{ 'Content-Type' = 'application\json'; 'Authorization' = $script:GraphAPIAccessToken.CreateAuthorizationHeader() }

    $QueryResults = @()
    if ($Method -eq "Get") {
        do {
            $Results = Invoke-RestMethod -Headers $Header -Uri $uri -UseBasicParsing -Method $Method -ContentType "application/json"
            if ($null -ne ($Results.value)) { $QueryResults += $Results.value }
            else { $QueryResults += $Results }          
            $uri = $Results.'@odata.nextlink'
        }until (!($uri))
    }
   
    Write-Progress -Id 1 -Activity "Executing query: $Uri" -Completed
    Return $QueryResults
 }
 catch {
     
 }
}

if(!(Test-Path .\POSHGraphHelpersConfig.json)){
    Write-Error "Configuration file, POSHGraphHelpersConfig.json, is missing. Ensure the configuration file is present in the same directory as the script and retry."
}
$script:GraphAPITenant = $null;
$script:GraphAPIClientId = $null;
$script:GraphAPIClientSecret = $null;
$script:GraphAPICerThumbprint = $null;