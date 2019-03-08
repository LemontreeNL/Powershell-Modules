<#	
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2018 v5.5.152
	 Created on:   	18/05/2018 2:09 PM
	 Created by:   	Jordy de Rooij
	 Organization: 	
	 Filename:     	Lemontree-Module.psm1
	-------------------------------------------------------------------------
	 Module Name: Lemontree-Module
	===========================================================================
#>

function Update-LemontreeModule
{
	[CmdletBinding()]
	param
	(
		[string]$ModuleURL = 'https://raw.githubusercontent.com/LemontreeNL/Powershell-Modules/master/Lemontree-Module.psm1',
		[string]$DestinationModulePath = 'C:\program files\Lemontree\module\Lemontree-Module.psm1'
	)
	
	(New-Object System.Net.WebClient).DownloadFile($ModuleURL, $DestinationModulePath)
}

function test-moduleupdate
{
	Write-Host 'hahaha'
}

function Verify-FileAgeNotOlderThen
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateScript({ test-path $_ })]
		[string]$Path,
		[Parameter(Mandatory = $true)]
		[int]$MaxAgeOfFileInDays
	)
	
	$File = Get-Item $Path
	$MaxAge = (Get-date).AddDays(- $MaxAgeOfFileInDays)
	
	if ($File.CreationTime -lt $MaxAge)
	{
		Return $true
	}
	Else
	{
		return $False
	}
	
}

function Write-EventLogLemontree
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$LogName = 'Lemontree',
		[Parameter(Mandatory = $true)]
		[string]$Source = 'NableAutomation',
		[string]$Message,
		[Parameter(Mandatory = $true)]
		[int]$EventID,
		[ValidateSet('Information', 'FailureAudit', 'Error', 'SuccessAudit', 'Warning')]
		[string]$EntryType = 'Information',
		[string]$Category,
		[String]$ComputerName,
		[Byte[]]$RawData
	)
	
	begin
	{
		#check if eventlog already exists, if not we have to create new logbook and source.
		if (-not ([System.Diagnostics.EventLog]::Exists($LogName) -and [System.Diagnostics.EventLog]::SourceExists($Source)))
		{
			New-EventLog -LogName $LogName -Source $Source
		}
	}
	Process
	{
		$ParametersEventlog = @{
			'LogName' = $LogName
			'Source'  = $Source
			'EventID' = $EventID
		}
		if ($EntryType) { $ParametersEventlog.add('EntryType', $EntryType) }
		if ($Message) { $ParametersEventlog.add('Message', $Message) }
		if ($Category) { $ParametersEventlog.add('Category', $Category) }
		if ($ComputerName) { $ParametersEventlog.add('ComputerName', $ComputerName) }
		if ($null -ne $RawData) { $ParametersEventlog.Add('RawData', $RawData) }
		
		Write-EventLog @ParametersEventlog
	}
}

function Get-DownloadFile
{
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$URL,
		[Parameter(Mandatory = $true)]
		[string]$Destination
	)
	
	$StartTime = Get-Date
	
	(New-Object System.Net.WebClient).DownloadFile($URL, $Destination)
	
	Write-Output ('Time Taken: {0} second(s)' -f $((Get-Date).Subtract($StartTime).Seconds))
}

function Write-Log
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true,
				   Position = 1)]
		[string]$message,
		[switch]$isError,
		[string]$color = 'Cyan',
		[int]$loglevel = [int]$loglevel,
		[string]$LogPath = $LogPath
	)
	
	begin
	{
		$spacer = "   " * $loglevel
		$outmessage = "[$loglevel] $(Get-Date -Format dd-MM-yyyy` ` hh:mm) :: $($spacer)$($message)`r"
	}
	
	Process
	{
		
		
		if ($isError)
		{
			Write-Warning "[$loglevel] $(Get-Date -Format dd-MM-yyyy` ` hh:mm) :: $($spacer)$($message)`r"
			$outmessage = "WARNING: " + $outmessage
		}
		Else
		{
			Write-Host ($outmessage) -ForegroundColor $color
		}
		if ($LogPath)
		{
			$outmessage | Out-File -FilePath $LogPath -Append
		}
	}
}

function Get-LMTPingStatistics
{
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $True, Position = 1)]
		[string]$inputfile
	)
	
	begin
	{
		$regexDate = "(?<date>\d{1,}-\d{1,}-\d{4})\s(?<time>\d{2}:\d{2}:\d{2})"
		$IPregex = '(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
	}
	Process
	{
		$CounterTimedOut = 0
		$CounterStreaks = 0
		$SourceServer = (Get-Content -Path $inputfile -TotalCount 1) -match "Hostname:\s(?<Source>.+)" | ForEach-Object { $matches.source }
		[datetime]$DateStarted = (Get-Content -Path $inputfile -TotalCount 1) -match $regexDate | ForEach-Object { ('{0}-{1}-{2} {3}' -f $matches.date.split('-')[1], $matches.date.split('-')[0], $matches.date.split('-')[2], $matches.time) }
		[datetime]$DateEnded = (Get-Content -Path $inputfile -Tail 1) -match $regexDate | ForEach-Object { ('{0}-{1}-{2} {3}' -f $matches.date.split('-')[1], $matches.date.split('-')[0], $matches.date.split('-')[2], $matches.time) }
		$TotalDuration = New-TimeSpan -Start $DateStarted -end $DateEnded
		
		$properties = [ordered]@{
			'Destination'	     = ""
			'SourceServer'	     = $SourceServer
			'StartTime'		     = ('{0:dd-MM HH:mm:ss}' -f $DateStarted)
			'EndTime'		     = ('{0:dd-MM HH:mm:ss}' -f $DateEnded)
			'TotalDuration'	     = ('{0} Days - {1} Hours, {2} Minutes, {3} Seconds' -f $TotalDuration.Days, $TotalDuration.Hours, $TotalDuration.Minutes, $TotalDuration.Seconds)
			'TotalPings'		 = 0
			'Succeeded'		     = 0
			'TimedOut'		     = 0
			'PercentLost'	     = 0
			'LongestStreak'	      = 0
			'NumberofStreaks'	= 0
		}
		$object = new-object -TypeName psobject -Property $properties
		
		foreach ($line in [system.IO.File]::ReadLines($inputfile))
		{
			if ($line -match "Request Timed Out.")
			{
				$line -match $regexDate | Out-Null
				[datetime]$DateTimeout = ('{0}-{1}-{2} {3}' -f $matches.date.split('-')[1], $matches.date.split('-')[0], $matches.date.split('-')[2], $matches.time)
				$CounterTimedOut++
				if ($counterTimedout -eq 1)
				{
					$DateStart = $DateTimeout
				}
				$object.TimedOut++
				$object.TotalPings++
				if ($object.LongestStreak -lt $CounterTimedOut)
				{
					$object.LongestStreak = $CounterTimedOut
				}
				
			}
			if ($line -match "Reply from ")
			{
				
				if ($CounterTimedOut -gt 1)
				{
					$CounterStreaks++
					$object.numberofstreaks++
					$object | Add-Member -MemberType NoteProperty -Name "Streak$($CounterStreaks)" -Value ('[{0:dd-MM} {1:HH:mm:ss}] :: Missed Timeouts [{2}] :: Lasted [{3}] Seconds' -f $DateStart, $DateStart, $CounterTimedout, ($CounterTimedout * 5))
					write-host ('Streak {0}:: [{1:dd-MM} {2:HH:mm:ss}] :: Missed Timeouts [{3}] :: Lasted [{4}] Seconds' -f $CounterStreaks, $DateStart, $DateStart, $CounterTimedout, ($CounterTimedout * 5))
					Remove-Variable datestart -ErrorAction SilentlyContinue
				}
				$CounterTimedOut = 0
				$object.Succeeded++
				$object.TotalPings++
				$IPaddress = $line
			}
		}
		
		#last check if there were timeouts, if script ends with timeout, that would mean it wouldn't be able to determine if it's a streak.
		#this would only be hit if the last line wasn't ended with a success, otherwise $counterTimedout would be 0.
		if ($CounterTimedOut -gt 1)
			{
				$CounterStreaks++
				$object.numberofstreaks++
				$object | Add-Member -MemberType NoteProperty -Name "Streak$($CounterStreaks)" -Value ('[{0:dd-MM} {1:HH:mm:ss}] :: Missed Timeouts [{2}] :: Lasted [{3}] Seconds' -f $DateStart, $DateStart, $CounterTimedout, ($CounterTimedout * 5))
				write-host ('Streak {0}:: [{1:dd-MM} {2:HH:mm:ss}] :: Missed Timeouts [{3}] :: Lasted [{4}] Seconds' -f $CounterStreaks, $DateStart, $DateStart, $CounterTimedout, ($CounterTimedout * 5))
				Remove-Variable datestart -ErrorAction SilentlyContinue
			}

		
		$IPaddress -match $IPRegex | Out-null
		$object.Destination = $matches.address
		$object.PercentLost = [math]::Round((($object.TimedOut * 100) / $object.TotalPings), 2)	
	}
	End
	{
		write-output $object
	}
}

function LMTPing
{
<#
	.SYNOPSIS
		Pings a destination with ability to log and show timestamps.
	
	.DESCRIPTION
		A detailed description of the LMTPing function.
	
	.PARAMETER destination
		Expacts a string, which can either be an IP address or a hostname.
	
	.PARAMETER log
		Switch parameter that enables the logging, this makes it so the IncludeLogging parameter set will be used and the output will be shown on the console and also in the file specified.
	
	.PARAMETER Path
		Path where the loggin has to be done. This folder has to be present before starting this ping.
	
	.PARAMETER filename
		Filename of the file where the logging has to be done.
	
	.EXAMPLE
				PS C:\> LMTPing
				PS C:\> LMTPing -destination 8.8.8.8 -log -path 'C:\Program Files\Lemontree\log' -filename 'Ping_8.8.8.8.txt'
	
	.NOTES
		Additional information about the function.
#>
	
	[CmdletBinding(DefaultParameterSetName = 'IncludeLogging')]
	param
	(
		[Parameter(Mandatory = $true,
				   Position = 1)]
		[string]$destination = (Read-Host "Specify destination host name or IP address"),
		[Parameter(ParameterSetName = 'IncludeLogging')]
		[switch]$log,
		[Parameter(ParameterSetName = 'IncludeLogging')]
		[string]$Path,
		[Parameter(ParameterSetName = 'IncludeLogging')]
		[string]$filename
	)
	
	begin
	{
		
	}
	Process
	{
		if ($log)
		{
			
			if ($Path)
			{
				$testpath = Test-Path $Path
				if (!($testpath))
				{
					Do
					{
						$Path = Read-Host "Please Specify the path for your logs? ( ex. 'C:\Temp' )"
					}
					Until ((Test-Path $Path) -eq $true)
				}
			}
			Else
			{
				Do
				{
					$Path = Read-Host "Please Specify the path for your logs? ( ex. 'C:\Temp' )"
				}
				Until ((Test-Path $Path) -eq $true)
				
			}
			
			
			if (!($filename))
			{
				$filename = Read-Host "Please Specify the filename for the logging. ( ex. PingGoogle.txt )"
			}
			
			Write-Output ('{0} - SourceServer Hostname: {1}' -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss"), $env:COMPUTERNAME) | Tee-Object -FilePath (Join-Path $Path $filename) -Append
			ping $destination -t | ForEach-Object { "{0} - {1}" -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss"), $_ } | tee-object -filepath (Join-Path $Path $filename) -append
		}
		Else
		{
			ping $destination -t | ForEach-Object { "{0} - {1}" -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss"), $_ }
		}
		
		
	}
	end
	{
		Write-Output 'Ping aborted' | Tee-Object -FilePath (Join-Path $Path $filename) -Append
		break;
	}
}

function Get-PublicIP
{
	[CmdletBinding()]
	param ()
	
	Invoke-RestMethod http://ipinfo.io/json
}

function Repair-LemontreeFolders
{
	[CmdletBinding()]
	param
	(
		[array]$Folders = @('tmp', 'log', 'bin', 'xml', 'scripts', 'module'),
		[string]$Root = 'C:\Program Files\Lemontree'
	)
	
	begin
	{
		#Check if Root folder is present
		try
		{
			if (-not (Test-Path $Root))
			{
				New-Item $Root -ItemType dir -ErrorAction Stop | Out-Null
			}
		}
		catch
		{
			Write-Output "Root folder not present, error during creation."
			Write-Output ('ERROR :: {0}' -f $Error[0].Exception.Message)
			Write-Output ('ERROR :: {0}' -f $Error[0].InvocationInfo)
			break;
		}
	}
	Process
	{
		#Checking existence of each folder, and if needed create them.
		foreach ($Folder in $folders)
		{
			try
			{
				if (-not (Test-Path (Join-Path $Root $Folder)))
				{
					New-Item (Join-Path $Root $Folder) -ItemType dir -ErrorAction Stop | Out-Null
					Write-Verbose ('{0} has been created.' -f (Join-Path $Root $Folder))
				}
				Else
				{
					Write-Verbose ('{0} is already present.' -f (Join-Path $Root $Folder))
				}
			}
			catch
			{
				write-output ('Error creating {0}' -f (Join-Path $Root $Folder))
				Write-Output ('ERROR :: {0}' -f $Error[0].Exception.Message)
			}
		}
	}
	End
	{
		##
	}
}

function Join-Parts
{
	param
	(
		$Parts = $null,
		$Separator = ''
	)
	
	($Parts | ? { $_ } | % { ([string]$_).trim($Separator) } | ? { $_ }) -join $Separator
}

function Check-LmtServiceVersion
{
	[CmdletBinding(DefaultParameterSetName = 'LatestVersion')]
	param
	(
		$VersionRootURL = 'https://lemontreenabletest.blob.core.windows.net/nablerepository/LmtSvc/',
		$serviceName = "Lemontree Orchestrator Service",
		$VersionFile = 'Service_Lmt_Orchestrator_Version.txt',
		[Parameter(ParameterSetName = 'LocalVersion',
				   Mandatory = $true)]
		[switch]$LocalVersion,
		[Parameter(ParameterSetName = 'LatestVersion',
				   Mandatory = $true)]
		[switch]$LatestVersion
	)
	
	begin
	{
		$VersionURL = (Join-Parts -Separator '/' -Parts $VersionRootURL, $VersionFile)
				
		if (-not ($LocalVersion -or $LatestVersion))
		{
			Write-Output 'No Parameter set given, either specify if LocalVersion or LatestVersion is needed. Aborting script!'
			throw;
		}
	}
	Process
	{
		if ($LocalVersion)
		{
			try
			{
				$FullPath = (Get-WmiObject Win32_Service | ? { $_.name -like $serviceName } | select -ExpandProperty pathname).trim('"')
				$file = Get-Item $FullPath -ErrorAction Stop
				$Version = New-Object System.Version -ArgumentList ($file.VersionInfo.fileversion)
				$RootPath = Split-Path $file
			}
			catch
			{
				$string = @"
	Couldn't Determine the version of the installed service.

	ERROR Message :: $($Error[0].Exception.Message)
	ERROR Line    :: $($Error[0].InvocationInfo.Line)
"@
				Write-Host $string
				throw;
			}
		}
		
		if ($LatestVersion)
		{
			try
			{
				$Version = New-Object System.Version -argumentlist (New-Object System.Net.WebClient).DownloadString($VersionURL)
			}
			Catch
			{
				$string = @"
	Cant determine the latest version available on the internet.

	URL Requested :: $VersionURL
	ERROR Message :: $($Error[0].Exception.Message)
	ERROR Line    :: $($Error[0].InvocationInfo.Line)
"@
				Write-Host $string
				throw;
			}
		}
	}
	End
	{
		Write-Output $Version
	}
}

function Update-LmtService
{
	[CmdletBinding()]
	param
	(
		$serviceName = "Lemontree Orchestrator Service",
		$ExecutableName = "Service_Lmt_Orchestrator.exe",
		$IntendedPathRoot = "c:\program files\Lemontree\bin\",
		$UpdateRootURL = 'https://lemontreenabletest.blob.core.windows.net/nablerepository/LmtSvc/'
	)
	
	Begin
	{
		$IntendedPath = Join-Path $IntendedPathRoot $ExecutableName
		$service = Get-Service $serviceName
		$UpdateURL = (Join-Parts -Separator '/' -Parts $UpdateRootURL, $ExecutableName)
		
		if ($service)
		{
			#If Service is present, determine the running path and version.
			try
			{
				$CurrentVersion = Check-LmtServiceVersion -LocalVersion -ErrorAction Stop
				$FullPath = (Get-WmiObject Win32_Service | ? { $_.name -like $serviceName } | select -ExpandProperty pathname).trim('"')
				$file = Get-Item $FullPath -ErrorAction Stop
				$RootPath = Split-Path $file
			}
			catch
			{
				$Output = @"
ERROR Message :: $($Error[0].Exception.Message)
ERROR Line    :: $($Error[0].InvocationInfo.Line)
"@
				Write-Host $Output
			}
		}
	}
	Process
	{
		if ($service)
		{
			if ($file)
			{
				$LatestVersion = Check-LmtServiceVersion -LatestVersion
				
				if ($LatestVersion -gt $CurrentVersion)
				{
					$string = @"
CurrentVersion :: $CurrentVersion
LatestVersion :: $LatestVersion `n
Downloading New version and installing the new service version.
"@
					
					Write-Host $string
					
					#Stop Service and Rename current executable.
					if ($service.Status -ne 'Stopped')
					{
						Stop-Service $serviceName
					}
					Start-Sleep 5
					try
					{
						Rename-Item $FullPath -newname (Join-Path $RootPath "$($file.BaseName)_old.exe") -Force
						
						#Download main script to run, and run it afterwards.
						(New-Object System.Net.WebClient).DownloadFile($UpdateURL, $FullPath)
						
						Start-Sleep 5
						& $FullPath /u
						Start-Sleep 5
						& $FullPath /i
						Start-Sleep 5
					}
					catch
					{
						$Output = @"
ERROR Message :: $($Error[0].Exception.Message)
ERROR Line    :: $($Error[0].InvocationInfo.Line)
"@
						
						Write-Host $Output
						
					}
					Start-Service $serviceName
					
				}
				elseif ($LatestVersion -eq $CurrentVersion)
				{
					$string = @"
CurrentVersion :: $CurrentVersion
LatestVersion :: $LatestVersion `n

Version is up to date.
"@
					
					Write-Host $string
				}
			}
			Else
			{
				try
				{
					(New-Object System.Net.WebClient).DownloadFile($UpdateURL, (Join-Path $IntendedPath $ExecutableName))
					
					Start-Sleep 5
					& (Join-Path $IntendedPath $ExecutableName) /u
					Start-Sleep 5
					& (Join-Path $IntendedPath $ExecutableName) /i
					Start-Sleep 5
					
				}
				catch
				{
					$Output = @"
ERROR Message :: $($Error[0].Exception.Message)
ERROR Line    :: $($Error[0].InvocationInfo.Line)
"@
					
					Write-Host $Output
				}
			}
		}
		Else
		{
			try
			{
				$string = @"
No Service detected for $serviceName

Installing the service.
"@
				
				(New-Object System.Net.WebClient).DownloadFile($UpdateURL, $IntendedPath)
				
				Start-Sleep 5
				& $IntendedPath /i
				Start-Sleep 5
				
				Start-Service $serviceName
				
			}
			catch
			{
				$Output = @"
ERROR Message :: $($Error[0].Exception.Message)
ERROR Line    :: $($Error[0].InvocationInfo.Line)
"@
				Write-Host $Output
			}
		}
	}
	End
	{
		$service = Get-Service $serviceName
		if ($service.Status -ne 'Running')
		{
			Start-Service $serviceName
		}
	}
	
}

function Lemontree-ThirdPartyInstall
{
	[CmdletBinding()]
	param (
		[string]$AgentURL,
		[string]$ClassicURL,
		[string]$Destination
	)
	
	
	
	#TODO: Place script here
}

Export-ModuleMember -Function Get-DownloadFile, Write-Log, LMTPing, Get-PublicIP, Get-LMTPingStatistics, Repair-LemontreeFolders, Join-Parts, Check-LmtServiceVersion, Update-LmtService, Verify-FileAgeNotOlderThen, Write-EventLogLemontree, update-lemontreemodule, test-moduleupdate