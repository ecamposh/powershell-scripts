# PowerShell script to list Rackspace Cloud Files containers for a specific region
# .\list-cf-containers.ps1 -Username "your_username" -ApiKey "your_api_key" -Region "DFW"

param (
    [Parameter(Mandatory=$true)]
    [string]$Username,
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    [Parameter(Mandatory=$true)]
    [string]$Region
)

# Configure identity endpoint based on region
$Region = $Region.ToUpper()
$identityEndpoint = "https://identity.api.rackspacecloud.com/v2.0"
if ($Region -eq "LON") {
    $identityEndpoint = "https://lon.identity.api.rackspacecloud.com/v2.0"
}

try {
    # Step 1: Authenticate
    $authUrl = "$identityEndpoint/tokens"
    $authBody = @{
        auth = @{
            "RAX-KSKEY:apiKeyCredentials" = @{
                username = $Username
                apiKey = $ApiKey
            }
        }
    } | ConvertTo-Json

    $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -ContentType "application/json" -Body $authBody

    $token = $authResponse.access.token.id

    # Find the storage URL for cloudFiles in the specified region
    $storageUrl = $null
    foreach ($service in $authResponse.access.serviceCatalog) {
        if ($service.name -eq "cloudFiles") {
            foreach ($endpoint in $service.endpoints) {
                if ($endpoint.region -eq $Region) {
                    $storageUrl = $endpoint.publicURL
                    break
                }
            }
            if ($storageUrl) { break }
        }
    }

    if (-not $storageUrl) {
        Write-Error "Could not find cloudFiles endpoint for region: $Region"
        exit 1
    }

    # Step 2: List containers
    $listUrl = "$storageUrl`?format=json"
    $headers = @{
        "X-Auth-Token" = $token
        "Accept" = "application/json"
    }

    $containers = Invoke-RestMethod -Uri $listUrl -Method Get -Headers $headers

    Write-Output "Containers in region $Region`:"
    foreach ($container in $containers) {
        Write-Output "- $($container.name) (Files: $($container.count), Bytes: $($container.bytes))"
    }
}
catch {
    Write-Error "Error: $($_.Exception.Message)"
}
