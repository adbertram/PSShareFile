function Request-ShareFileAccessToken {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ClientId,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ClientSecret,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Username,
		
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Password
	)

	$ErrorActionPreference = 'Stop'

	try {

		$authInfo = Get-ShareFileApiAuthInfo
		if (-not $authInfo -and -not $ClientId) {
			throw 'Could not find auth info in the registry. Either use Save-ShareFileApiAuthInfo to save information or use the parameters on this function.'
		} elseif ($ClientId) {
			$authInfo = [pscustomobject]@{
				ClientId     = $ClientId
				ClientSecret = $ClientSecret
				Username     = $Username
				Password     = $Password
			}
		}

		$payload = @{
			'grant_type'    = 'password'
			'client_id'     = [System.Uri]::EscapeUriString($authInfo.ClientId) 
			'client_secret' = [System.Uri]::EscapeUriString($authInfo.ClientSecret) 
			'username'      = $authInfo.Username
			'password'      = [System.Uri]::EscapeUriString($authInfo.Password)
		}

		$endpointAuthUri = "https://$$($authInfo.AccountName).sharefile.com/oauth/token"
		$headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }

		$result = Invoke-RestMethod -Uri $endpointAuthUri -Headers $headers -Method GET -Body $payload
		Save-ShareFileApiAuthInfo -Token $result.access_token
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Get-ShareFileApiAuthInfo {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$RegistryKeyPath = 'HKCU:\Software\PSShareFile'
	)
	
	$ErrorActionPreference = 'Stop'

	function decrypt([string]$TextToDecrypt) {
		$secure = ConvertTo-SecureString $TextToDecrypt
		$hook = New-Object system.Management.Automation.PSCredential("test", $secure)
		$plain = $hook.GetNetworkCredential().Password
		return $plain
	}

	try {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			Write-Warning 'No PSShareFile API info found in registry'
		} else {
			$keys = (Get-Item -Path $RegistryKeyPath).Property
			$ht = @{}
			foreach ($key in $keys) {
				$ht[$key] = decrypt (Get-ItemProperty -Path $RegistryKeyPath).$key
			}
			[pscustomobject]$ht
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Save-ShareFileApiAuthInfo {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$ClientId,

		[Parameter()]
		[string]$ClientSecret,

		[Parameter()]
		[string]$Username,
	
		[Parameter()]
		[string]$Password,

		[Parameter()]
		[string]$AccountName,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Token,
	
		[Parameter()]
		[string]$RegistryKeyPath = "HKCU:\Software\PSShareFile"
	)

	begin {
		function encrypt([string]$TextToEncrypt) {
			$secure = ConvertTo-SecureString $TextToEncrypt -AsPlainText -Force
			$encrypted = $secure | ConvertFrom-SecureString
			return $encrypted
		}
	}
	
	process {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			New-Item -Path ($RegistryKeyPath | Split-Path -Parent) -Name ($RegistryKeyPath | Split-Path -Leaf) | Out-Null
		}
		
		$values = $PSBoundParameters.GetEnumerator().where({ $_.Key -ne 'RegistryKeyPath' -and $_.Value}) | Select-Object -ExpandProperty Key
		
		foreach ($val in $values) {
			Write-Verbose "Creating $RegistryKeyPath\$val"
			New-ItemProperty $RegistryKeyPath -Name $val -Value $(encrypt $((Get-Variable $val).Value)) -Force | Out-Null
		}
	}
}

function Get-ShareFileFolder {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Path
	)

	$ErrorActionPreference = 'Stop'

	$authInfo = Get-ShareFileApiAuthInfo

	try {
		$headers = @{ 'Authorization' = "Bearer $($authInfo.Token)" }
		$payload = @{ 'path' = $Path }
		$uri = "https://$($authInfo.AccountName).sf-api.com/sf/v3/Items/ByPath"
		Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -Body $payload
	} catch {
		switch (($_.ErrorDetails.Message | ConvertFrom-Json).code) {
			'NotFound' {
				Write-Verbose -Message "The folder [$($Path)] was not found."
				break
			}
			'Unauthorized' {
				## Get another token
				Request-ShareFileAccessToken
				Get-ShareFileFolder @PSBoundParameters
				break
			}
			default {
				$PSCmdlet.ThrowTerminatingError($_)
			}
		}
	}
}

function Get-ShareFileUser {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$EmailAddress
	)

	$ErrorActionPreference = 'Stop'

	$authInfo = Get-ShareFileApiAuthInfo

	try {
		$headers = @{ 'Authorization' = "Bearer $($authInfo.Token)" }
		$payload = @{ 'emailAddress' = $EmailAddress }
	
		$uri = "https://$$($authInfo.AccountName).sf-api.com/sf/v3/Users"
		Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -Body $payload

	} catch {
		switch (($_.ErrorDetails.Message | ConvertFrom-Json).code) {
			'NotFound' {
				Write-Verbose -Message "The folder [$($Path)] was not found."
				break
			}
			'Unauthorized' {
				## Get another token
				Request-ShareFileAccessToken
				Get-ShareFileFolder @PSBoundParameters
				break
			}
			default {
				$PSCmdlet.ThrowTerminatingError($_)
			}
		}
	}
}

function New-ShareFileFolder {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ParentFolderId,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)

	$ErrorActionPreference = 'Stop'
	
	$authInfo = Get-ShareFileApiAuthInfo

	try {
		$headers = @{ 'Authorization' = "Bearer $($authInfo.Token)" }
		$payload = @{ 'Name' = $Name }
		
		$uri = "https://$($authInfo.AccountName).sf-api.com/sf/v3/Items($ParentFolderId)/Folder"
		Invoke-RestMethod -Uri $uri -Headers $headers -Method POST -Body $payload

	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
	}
}