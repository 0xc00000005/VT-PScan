# The script will be called with a file directory as a parameter, so we have to declare it in.
# To declare multiple parameters, they must be written in the same order they will be called.
param (
    [string]$file
)
# Call CredentialManager to retrieve the API key from the Windows Credential Manager.
# The module has to be installed in the host first.
$credential = Get-StoredCredential -Target "VT-Api"
$apiKey = $credential.GetNetworkCredential().Password
# Declare the ConvertTo-VTBody function
# It correctly formats the file to be able to send it as the body of the Request.
function ConvertTo-VTBody {
    <#
    .SYNOPSIS
    Converts file to memory stream to create body for Invoke-RestMethod and send it to Virus Total.
    #>

    [cmdletBinding()]
    param(
        [parameter(Mandatory)][System.IO.FileInfo] $FileInformation,
        [string] $Boundary
    )
    [byte[]] $CRLF = 13, 10 # ASCII code for CRLF

    $MemoryStream = [System.IO.MemoryStream]::new()

    $BoundaryInformation = [System.Text.Encoding]::ASCII.GetBytes("--$Boundary")
    $MemoryStream.Write($BoundaryInformation, 0, $BoundaryInformation.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    $FileData = [System.Text.Encoding]::ASCII.GetBytes("Content-Disposition: form-data; name=`"file`"; filename=$($FileInformation.Name);")
    $MemoryStream.Write($FileData, 0, $FileData.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    $ContentType = [System.Text.Encoding]::ASCII.GetBytes('Content-Type:application/octet-stream')
    $MemoryStream.Write($ContentType, 0, $ContentType.Length)

    $MemoryStream.Write($CRLF, 0, $CRLF.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    $FileContent = [System.IO.File]::ReadAllBytes($FileInformation.FullName)
    $MemoryStream.Write($FileContent, 0, $FileContent.Length)

    $MemoryStream.Write($CRLF, 0, $CRLF.Length)
    $MemoryStream.Write($BoundaryInformation, 0, $BoundaryInformation.Length)

    $Closure = [System.Text.Encoding]::ASCII.GetBytes('--')
    $MemoryStream.Write($Closure, 0, $Closure.Length)
    $MemoryStream.Write($CRLF, 0, $CRLF.Length)

    , $MemoryStream.ToArray()
}
# Create a function to store the response in a JSON file
function Save-ResponseToJson {
    param (
        [string]$responseContent,
        [string]$fileName
    )

    $folderPath = "$env:LOCALAPPDATA\VT-PScan\Stats"
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath | Out-Null
    }

    $filePath = Join-Path -Path $folderPath -ChildPath "$fileName.json"
    $responseContent | ConvertTo-Json | Out-File -FilePath $filePath -Encoding UTF8
}
# We declare the necessary code to show message boxes.
Add-Type -AssemblyName PresentationCore,PresentationFramework
$ButtonType = [System.Windows.MessageBoxButton]::OK
$MessageIconSafe = [System.Windows.MessageBoxImage]::Information
$MessageIconSus = [System.Windows.MessageBoxImage]::Warning
$MessageIconMal = [System.Windows.MessageBoxImage]::Error
$MessageTitle = "Results of the scan"
# We save in the variable $hashObject the hash of the file passed as a parameter, but don't Format-Table 
# to hide the table headers and only show the hash beacuse it's intended for output as it includes formatting characters..
# Important to know that the output of Get-FileHash is an object, which has different "properties" 
# (like Hash, Path, Algorithm, etc.), making it easy to work with ($hashObject.Hash).
$hashObject = Get-FileHash -Path "$file" -Algorithm SHA256
$sha256 = $hashObject.Hash
# Create empty hash table (key-value pairs) to store the headers.
$headers=@{}
$headers.Add("accept", "application/json")
$headers.Add("x-apikey", $apiKey)
# We make a WebRequest to the API using "" insted of '' to allow the variable $sha256 to be interpreted.
$response = Invoke-WebRequest -Uri "https://www.virustotal.com/api/v3/files/$sha256" -Method GET -Headers $headers
$dateTime = Get-Date -Format "yyyyMMdd_HHmmss"

if ($response.StatusCode -eq 200) {
    Save-ResponseToJson -responseContent $response.Content -fileName $dateTime
    # It's converted from JSON to a PowerShell object, and spawns Windows message boxes with the results.
   $responsecont = $response.Content | ConvertFrom-Json
if ($responsecont.data.attributes.last_analysis_stats.malicious -eq 0 -and $responsecont.data.attributes.last_analysis_stats.suspicious -eq 0) {
    [System.Windows.MessageBox]::Show("This file seems to be completely safe.",$MessageTitle,$ButtonType,$MessageIconSafe)
   }
    elseif ($responsecont.data.attributes.last_analysis_stats.malicious -eq 0 -and $responsecont.data.attributes.last_analysis_stats.suspicious -gt 0) {
        $resultssus = "This file is not detected as malicious but it was detected as suspicious by " + $responsecont.data.attributes.last_analysis_stats.suspicious + " engines, and a reptutation of " + $responsecont.data.attributes.reputation
        [System.Windows.MessageBox]::Show($resultssus,$MessageTitle,$ButtonType,$MessageIconSus)
    }
    else {
        $resultsmal = "This file is as malicious by " + $responsecont.data.attributes.last_analysis_stats.malicious + " engines, suspicious by "+ $responsecont.data.attributes.last_analysis_stats.suspicious + " engines, and has a reptutation of " + $responsecont.data.attributes.reputation + ". DO NOT RUN."
        [System.Windows.MessageBox]::Show($resultsmal,$MessageTitle,$ButtonType,$MessageIconMal)
   }
} 
else {
    # If the status code is not 200, it should be 400 indicating that the file is not in the VirusTotal database.
    # Then it will check if it's small enough and send it for analysis.
    # Check if the file size is less than or equal to 32MB (33554432 bytes)
    $fileSize = (Get-Item -Path $file).Length
    if ($fileSize -le 33554432) {
        # Get the file extension without the '.'
        $Boundary = [Guid]::NewGuid().ToString().Replace('-', '')
        $Body = ConvertTo-VTBody -File $File -Boundary $Boundary
        $ContentType = 'multipart/form-data; boundary=' + $Boundary
        $response = Invoke-WebRequest -Uri 'https://www.virustotal.com/api/v3/files' -Method POST -Headers $headers -Body $Body -ContentType $ContentType
        $responselink = $response.Content | ConvertFrom-Json
        $responselink.data.links.self
        $headers.Remove("accept")
        $analysis = Invoke-WebRequest -Uri $responselink.data.links.self -Method GET -Headers $headers
        $dateTime = Get-Date -Format "yyyyMMdd_HHmmss"
        Save-ResponseToJson -responseContent $analysis.Content -fileName $dateTime
        $analysiscont = $analysis.Content | ConvertFrom-Json
        if ($analysiscont.data.attributes.stats.malicious -eq 0 -and $analysiscont.data.attributes.stats.suspicious -eq 0) {
            [System.Windows.MessageBox]::Show("This file seems to be completely safe.",$MessageTitle,$ButtonType,$MessageIconSafe)
           }
            elseif ($analysiscont.data.attributes.stats.malicious -eq 0 -and $analysiscont.data.attributes.stats.suspicious -gt 0) {
                $resultssus = "This file is not detected as malicious but it was detected as suspicious by " + $analysiscont.data.attributes.stats.suspicious + " engines, and a reptutation of " + $analysiscont.data.attributes.reputation
                [System.Windows.MessageBox]::Show($resultssus,$MessageTitle,$ButtonType,$MessageIconSus)
            }
            else {
                $resultsmal = "This file is as malicious by " + $analysiscont.data.attributes.stats.malicious + " engines, suspicious by "+ $analysiscont.data.attributes.stats.suspicious + " engines, and has a reptutation of " + $analysiscont.data.attributes.reputation + ". DO NOT RUN."
                [System.Windows.MessageBox]::Show($resultsmal,$MessageTitle,$ButtonType,$MessageIconMal)
           }
        } 
      else {
            [System.Windows.MessageBox]::Show("The file is too large to be analyzed by VirusTotal.", $MessageTitle, $ButtonType, $MessageIconMal)
        }
}

