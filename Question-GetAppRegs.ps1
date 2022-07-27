#########
# au2mator PS Services
# Type: PowerShell Question
#
# Title: AZURE - GetUsers
#
# URL: https://au2mator.com/documentation/configure-powershell-question-type/?utm_source=github&utm_medium=social&utm_campaign=AZURE_RemoveSecretFromAppReg&utm_content=PS1
# Github: https://github.com/au2mator/au2mator-PS-Templates
#
# PreReq: au2mator 4.5 or higher required
#
#
#
# au2mator is happy to support you with your Automation
# Contact us here: https://au2mator.com/premier-services/?utm_source=github&utm_medium=social&utm_campaign=AZURE_RemoveSecretFromAppReg&utm_content=PS1
#
#################


#Param
param ($au2matorhook)

#Environment
[string]$CredentialStorePath = "C:\_SCOworkingDir\TFS\PS-Services\CredentialStore" #see for details: https://au2mator.com/documentation/powershell-credentials/?utm_source=github&utm_medium=social&utm_campaign=AZURE_RemoveSecretFromAppReg&utm_content=PS1
[string]$LogPath = "C:\_SCOworkingDir\TFS\PS-Services\AZURE - Delete Secret from Azure App Reg\Logs"
[string]$LogfileName = "Question-GetAppRegs"

#MS Graph Cred
$MSGraphAPICred_File = "MSGraphAPICred.xml"
$MSGraphAPICred = Import-CliXml -Path (Get-ChildItem -Path $CredentialStorePath -Filter $MSGraphAPICred_File).FullName
$MSGraphAPI_clientId = $MSGraphAPICred.clientId
$MSGraphAPI_clientSecret = $MSGraphAPICred.clientSecret
$MSGraphAPI_tenantID = $MSGraphAPICred.tenantName


#region Functions
function Write-au2matorLog {
    [CmdletBinding()]
    param
    (
        [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
        [string]$Type,
        [string]$Text
    )

    # Set logging path
    if (!(Test-Path -Path $logPath)) {
        try {
            $null = New-Item -Path $logPath -ItemType Directory
            Write-Verbose ("Path: ""{0}"" was created." -f $logPath)
        }
        catch {
            Write-Verbose ("Path: ""{0}"" couldn't be created." -f $logPath)
        }
    }
    else {
        Write-Verbose ("Path: ""{0}"" already exists." -f $logPath)
    }
    [string]$logFile = '{0}\{1}_{2}.log' -f $logPath, $(Get-Date -Format 'yyyyMMdd'), $LogfileName
    $logEntry = '{0}: <{1}> <{2}> <{3}> {4}' -f $(Get-Date -Format dd.MM.yyyy-HH:mm:ss), $Type, $RequestId, $Service, $Text
    Add-Content -Path $logFile -Value $logEntry
}

#endregion Functions



try {
    Write-au2matorLog -Type INFO -Text "Try to connect to MSGraph  API"
    
    $tokenBody = @{  
        Grant_Type    = "client_credentials"  
        Scope         = "https://graph.microsoft.com/.default"  
        Client_Id     = $MSGraphAPI_clientId  
        Client_Secret = $MSGraphAPI_clientSecret  
    }   
  
    $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$MSGraphAPI_tenantID/oauth2/v2.0/token" -Method POST -Body $tokenBody  

    $headers = @{
        "Authorization" = "Bearer $($tokenResponse.access_token)"
        "Content-type"  = "application/json"
    }
    
    try {
        Write-au2matorLog -Type INFO -Text "Try to get Applications"
        $URL = "https://graph.microsoft.com/v1.0/applications"
        
        $ApplicationList = Invoke-RestMethod -Method GET -URI $URL -headers $headers 
        $ReturnList = @()

        foreach ($App in $ApplicationList.value) {
            
            $PSObject = New-Object -TypeName PSObject
            $PSObject | Add-Member -MemberType NoteProperty -Name App -Value "$($App.displayName) - ($($App.id))"
                       
            $ReturnList += $PSObject
        }
    }
    catch {
        Write-au2matorLog -Type ERROR -Text "Error to get Applications"
        Write-au2matorLog -Type ERROR -Text $Error
    
        $au2matorReturn = "Error to get Applications, Error: $Error"
        return $au2matorReturn
    }
}
catch {
    Write-au2matorLog -Type ERROR -Text "Failed to connect to Azure Rest API"
    Write-au2matorLog -Type ERROR -Text $Error

    $au2matorReturn = "Failed to connect to Azure Rest API, Error: $Error"
    return $au2matorReturn
}

return $ReturnList