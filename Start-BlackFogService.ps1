<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2019 v5.6.156
	 Created on:   	06/02/2019 13:53
	 Created by:   	Jordy de Rooij
	 Organization: 	
	 Filename:     	
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>

Get-Service 'Privacy Service' | Set-Service -StartupType Automatic
Start-Sleep -Seconds 5
Start-Service 'Privacy Service'
