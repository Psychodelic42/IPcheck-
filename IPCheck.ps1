# Set the API key for Virustotal
$apiKey = "ADD API KEY HERE"

# Read in the list of connections from a text file
$connections = Get-Content -Path "PATH TO TEXTFILE"

# Extract the non-private IP addresses from the connections
$ipList = foreach ($conn in $connections) {
    $match = $conn -match '(?:\d{1,3}\.){3}\d{1,3}'
    if ($match) {
        $ip = $matches[0]
        if ($ip -notmatch '^192\.168\.|^10\.|^172\.(?:1[6-9]|2\d|3[01])\.|^169\.254\.|^0\.0\.0\.0|^127\.0\.0\.1') {
            $ip
        }
    }
}

# Loop through each IP address and submit it to Virustotal
foreach ($ip in $ipList) {
    $url = "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=$apiKey&ip=$ip"
    $response = Invoke-RestMethod -Uri $url -Method Get
    
    # Get the status of the IP address from Virustotal
    $status = "Unknown"
    if ($response.detected_communicating_samples -ne $null) {
        $status = "Malicious"
    } elseif ($response.resolutions -ne $null) {
        $status = "Clean"
    }
    
    # Output the IP address and its status
    Write-Output "$ip : $status"
}
