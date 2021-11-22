$ovc = "<OVCIP>"
$username = "<USERNAME>"
$pass_word = "<PASSWORD>"
$output = @()
$backup_failed_count = 0

#Ignore Self Signed Certificates and set TLS
Try {
Add-Type @"
       using System.Net;
       using System.Security.Cryptography.X509Certificates;
       public class TrustAllCertsPolicy : ICertificatePolicy {
           public bool CheckValidationResult(
               ServicePoint srvPoint, X509Certificate certificate,
               WebRequest request, int certificateProblem) {
               return true;
           }
       }
"@
   [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
   [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} Catch {
}

# Authenticate - Get SVT Access Token
$uri = "https://" + $ovc + "/api/oauth/token"
$base64 = [Convert]::ToBase64String([System.Text.UTF8Encoding]::UTF8.GetBytes("simplivity:"))
$body = @{username="$username";password="$pass_word";grant_type="password"}
$headers = @{}
$headers.Add("Authorization", "Basic $base64")
$response = Invoke-RestMethod -Uri $uri -Headers $headers -Body $body -Method Post 
    
$atoken = $response.access_token

# Create SVT Auth Header
$headers = @{}
$headers.Add("Authorization", "Bearer $atoken")

# Get Date Back 24 Hours - Format Correctly for SVT REST API
$yesterday = (get-date).AddHours(-24)
$yesterday = $yesterday.ToUniversalTime()
$createdafter = (get-date $yesterday -format s) + "Z"

# Get OmniStack Clusters in Federation
#$uri = "https://" + $ovc + "/api/omnistack_clusters"
#$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

# Get virtual machines
$uri = "https://" + $ovc + "/api/virtual_machines"
$response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

For ($i=0; $i -lt [int]$response.count; $i++) {
    Write-Host "VM naam:" $response.virtual_machines[$i].name
    
    # Get Backups in virtual machines
    $uri = "https://" + $ovc + "/api/backups?show_optional_fields=false&virtual_machine_name=" + $response.virtual_machines[$i].name + "&created_after=" + $createdafter
    $bursp = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
    $destination_cluster = $bursp.backups.omnistack_cluster_name | Sort-Object | Get-Unique
    
    
    foreach ($backups in $bursp.backups){
        $backups.state
        $backup_failed_count
        if ($backups.state -ne "PROTECTED"){
            $backup_failed_count++
        }
    }
    
    if ($backup_failed_count -eq 0){
        $Backup_Status = "PROTECTED"
        $backup_failed_count = 0
    }
    else {
         $Backup_Status = "FAILED"
         $backup_failed_count = 0
    }

    $Output += New-Object -TypeName psobject -Property @{Servername = $response.virtual_machines[$i].name; Statusbackup = $Backup_Status; Destination_cluster = $destination_cluster; Backup_count = $bursp.count}
}