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
	
	$CounterTimedOut = 0
	$CounterStreaks = 0
	$regexDate = "(?<date>\d{1,}-\d{1,}-\d{4})\s(?<time>\d{2}:\d{2}:\d{2})"
	$IPregex = '(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
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
		'LongestStreak'	     = 0
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
				$object | Add-Member -MemberType NoteProperty -Name "Streak$($CounterStreaks)" -Value ('[{0:dd-MM} {1:hh:mm:ss}] :: Missed Timeouts [{2}] :: Lasted [{3}] Seconds' -f $DateStart, $DateStart, $CounterTimedout, ($CounterTimedout * 5))
				write-host ('Streak {0}:: [{1:dd-MM} {2:hh:mm:ss}] :: Missed Timeouts [{3}] :: Lasted [{4}] Seconds' -f $CounterStreaks, $DateStart, $DateStart, $CounterTimedout, ($CounterTimedout * 5))
				Remove-Variable datestart -ErrorAction SilentlyContinue
			}
			$CounterTimedOut = 0
			$object.Succeeded++
			$object.TotalPings++
			$IPaddress = $line
		}
	}
	$IPaddress -match $IPRegex | Out-null
	$object.Destination = $matches.address
	$object.PercentLost = [math]::Round((($object.TimedOut * 100) / $object.TotalPings), 2)
	
	write-output $object
}

function LMTPing
{
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
			
			Write-Output ('{0} - SourceServer Hostname: {1}' -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss"), $env:COMPUTERNAME) | Tee-Object -FilePath "$Path\$filename" -Append
			ping $destination -t | ForEach-Object { "{0} - {1}" -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss"), $_ } | tee-object -filepath "$Path\$filename" -append
		}
		Else
		{
			ping $destination -t | ForEach-Object { "{0} - {1}" -f (Get-Date -Format "dd-MM-yyyy HH:mm:ss"), $_ }
		}
		
		
	}
	end
	{
		Write-Output 'Ping aborted' | Tee-Object -FilePath "$Path\$filename" -Append
		break;
	}
}

function Get-PublicIP
{
	[CmdletBinding()]
	param ()
	
	Invoke-RestMethod http://ipinfo.io/json
}

Export-ModuleMember -Function Get-DownloadFile, Write-Log, LMTPing, Get-PublicIP, Get-LMTPingStatistics