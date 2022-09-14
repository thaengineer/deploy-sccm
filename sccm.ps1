$StateFile    = "C:\Temp\state.txt"
$DomainName   = "homelabcoderz.com"
$ADDSHostName = "DC01"
$SCCMHostName = "CM01"
# $SiteCode     = "S01"
$NIC          = (Get-NetAdapter).Name
$IPAddress    = "10.0.0.3"
$PrefixLen    = 24
$GateWay      = "10.0.0.1"
$DNSServers   = ("10.0.0.2", "1.1.1.1")
$SCCMFeatures = Get-Content -Path '.\sccm-features.txt'
$DomainAdmin  = "$DomainName\Administrator"
$Pass         = ConvertTo-SecureString -String "Password?123" -AsPlainText -Force
$Credential   = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainAdmin, $Pass


if(! (Test-Path -Path "C:\Temp"))
{
    New-Item -Path "C:\" -Name "Temp" -ItemType Directory | Out-Null
}


if(! (Test-Path -Path "C:\Temp\state.txt"))
{
    New-Item -Path "C:\Temp" -Name "state.txt" -ItemType File | Out-Null
    "0" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 0)
{
    Write-Host "joining: [$(Get-Date -Format "HH:mm:ss")] [$SCCMHostName -> $DomainName]"

    New-NetIPAddress -IPAddress $IPAddress -InterfaceAlias $NIC -DefaultGateway $GateWay -AddressFamily "IPv4" -PrefixLength $PrefixLen
    Set-DnsClientServerAddress -InterfaceAlias $NIC -ServerAddresses $DNSServers

    Add-Computer -Credential $Credential -DomainName $DomainName -Server $ADDSHostName -NewName $SCCMHostName -Restart

    "1" | Out-File -FilePath $StateFile
}


# NEED TO REWRITE THIS, IT WILL FAIL
if((Get-Content $StateFile) -eq 1)
{
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [SCCM Features]"

    foreach($feature in $SCCMFeatures)
    {
        if((Get-WindowsFeature -Name "$feature").InstallState -ne 'Installed')
        {
            Install-WindowsFeature -Name "$feature" -ComputerName $SCCMHostname
        }
    }

    "2" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 2)
{
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [MDT]"

    Start-Process -FilePath "C:\Windows\System32\msiexec.exe" -ArgumentList "/i C:\Media\MDT\MicrosoftDeploymentToolkit_x64.msi /q /n /norestart" -Wait -WindowStyle Hidden

    "3" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 3)
{
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [ADK]"

    Start-Process -FilePath "C:\Media\ADK\adksetup.exe" -ArgumentList '/ceip off /norestart /features OptionId.DeploymentTools OptionId.UserStateMigrationTool /q' -Wait -WindowStyle Hidden
    Start-Process -FilePath "C:\Media\ADKPE\adksetup.exe" -ArgumentList '/ceip off /norestart /features OptionId.WindowsPreinstallationEnvironment /q' -Wait -WindowStyle Hidden

    "4" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 4)
{
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [Microsoft SQL Server]"

    Start-Process -FilePath "C:\Media\SQL\setup.exe" -ArgumentList "/CONFIGURATIONFILE=C:\Media\SQL\ConfigurationFile.ini /IACCEPTSQLSERVERLICENSETERMS" -Wait -WindowStyle Hidden
    Start-Process -FilePath "C:\Media\SQL\SQLServerReportingServices.exe" -ArgumentList "/passive /norestart /IAcceptLicenseTerms /Edition=Eval" -Wait -WindowStyle Hidden
    Start-Process -FilePath "C:\Media\SQL\SSMS-Setup-ENU.exe" -ArgumentList "/install /passive /norestart" -Wait -WindowStyle Hidden

    "5" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 5)
{
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [System Center Configuration Manager]"

    Start-Process -FilePath "C:\Media\SCCM\SMSSETUP\BIN\X64\setup.exe" -ArgumentList "/script C:\Media\SCCM\ConfigMgr.ini" -Wait -WindowStyle Hidden

    "6" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 6)
{
    Remove-Item -Path $StateFile | Out-Null

    Write-Host "done: [$(Get-Date -Format "HH:mm:ss")]"
}


#$PayLoad = {
#    Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Private
#}
#Invoke-Command -ComputerName $ADDSHostName -ScriptBlock $PayLoad
