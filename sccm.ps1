$SCCMFeatures = Get-Content -Path '.\sccm-features.txt'
$SCCMHostname = 'SCCMVM'


Write-Host "Installing required features for SCCM..."

foreach($feature in $SCCMFeatures)
{
    if((Get-WindowsFeature -Name "$feature").InstallState -ne 'Installed')
    {
        Install-WindowsFeature -Name "$feature" -ComputerName $SCCMHostname
    }
}


Write-Output 'Extending AD Schema...'
Start-Process -FilePath "C:\Media\SCCM\SMSSETUP\BIN\X64\extadsch.exe" -wait -WindowStyle Hidden

Write-Output 'Installing MDT...'
Start-Process -FilePath Msiexec.exe -ArgumentList "/i C:\Media\MDT\MicrosoftDeploymentToolkit_x64.msi /q /n /norestart" -wait -WindowStyle Hidden

Write-Output 'Installing Windows ADK...'
Start-Process -FilePath "C:\Media\ADK\adksetup.exe" -ArgumentList '/ceip off /norestart /features OptionId.DeploymentTools OptionId.UserStateMigrationTool /q' -wait -WindowStyle Hidden
Start-Process -FilePath "C:\Media\ADKPE\adksetup.exe" -ArgumentList '/ceip off /norestart /features OptionId.WindowsPreinstallationEnvironment /q' -wait -WindowStyle Hidden

Write-Output 'Installing Microsoft SQL Server...'
Start-Process -FilePath "C:\Media\SQL\setup.exe" -ArgumentList "/CONFIGURATIONFILE=C:\Media\SQL\ConfigurationFile.ini /IACCEPTSQLSERVERLICENSETERMS" -wait -WindowStyle Hidden
Start-Process -FilePath "C:\Media\SQL\SQLServerReportingServices.exe" -ArgumentList "/passive /norestart /IAcceptLicenseTerms /Edition=Eval" -wait -WindowStyle Hidden
Start-Process -FilePath "C:\Media\SQL\SSMS-Setup-ENU.exe" -ArgumentList "/install /passive /norestart" -wait -WindowStyle Hidden


#$Credential = Get-Credential -Message 'Enter SQL Service Account ID and Password.'
#$UserName=$Credential.UserName
#$Password=$Credential.getnetworkcredential().Password
#$s=Get-CimInstance -ClassName win32_service -Filter 'Name="MSSQLSERVER"'    
#Write-Output 'Assigning Credentials to SQL Server Service'
#Stop-Service -Force -NoWait -Name MSSQLSERVER
#$s | Invoke-CimMethod -MethodName Change -Arguments @{StartName=$Username ;StartPassword=$Password}
#Start-Sleep -Seconds 10
#Start-Service -Name MSSQLSERVER
#Remove-Variable Username
#Remove-Variable Password

#$FQDN=[system.net.dns]::GetHostByName("localhost").hostname

Write-Output 'Installing SCCM...'

# Change Service Account Credentials
Start-Process -FilePath "C:\Media\SCCM\SMSSETUP\BIN\X64\setup.exe" -ArgumentList "/script C:\Media\SCCM\ConfigMgr.ini" -wait -WindowStyle Hidden

Write-Output 'Done!'
Write-Output 'Please arrange for Post installation Configuration for the site'
