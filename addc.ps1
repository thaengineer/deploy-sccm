$ADDCFeatures = Get-Content -Path '.\dsdc-features.txt'
$state_file = "C:\Temp\state.txt"
$DomainName = "homelabcoderz.com"
$pass       = ConvertTo-SecureString "Password?123" -AsPlainText -Force


# ((Get-WindowsFeature) | where { $_.InstallState -eq 'Installed' })


if(! (Test-Path -Path "C:\Temp"))
{
    New-Item -Path "C:\" -Name "Temp" -ItemType Directory | Out-Null
    if(! (Test-Path -Path "C:\Temp\state.txt"))
    {
        New-Item -Path "C:\Temp" -Name "state.txt" -ItemType File | Out-Null
        "0" | OutFile -FilePath $state_file
    }
}


if((Get-Content $state_file) -eq 0)
{    
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [Active Directory Domain Services]"
    Install-WindowsFeature -name "AD-Domain-Services" -IncludeManagementTools

    Install-ADDSForest -DomainName "homelabcoderz.com" -SafeModeAdministratorPassword $pass -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012R2" -DomainNetbiosName "HOMELABCODERZ" -ForestMode "Win2012R2" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$true -SysvolPath "C:\Windows\SYSVOL" -Force:$true -Verbose

    "1" | Out-File -FilePath $state_file
}


if((Get-Content $state_file) -eq 1)
{
    $NIC         = (Get-NetAdapter).Name
    $IPAddress   = "192.168.160.2"
    $NetMask     = "255.255.255.0"
    $PrefixLen   = 24
    $GateWay     = "192.168.160.1"
    $DNSServers = ("1.1.1.1", "1.0.0.1")
    $HostName    = "DC01"

    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [DHCP]"
    Install-WindowsFeature -name "DHCP" -IncludeManagementTools

    Add-DhcpServerv4Scope -Name "Scope" -StartRange "192.168.160.2" -EndRange "192.168.160.200" -SubnetMask "255.255.255.0" -LeaseDuration 8.00:00:00
    Add-DhcpServerInDC -DnsName $HostName.$DomainName -IPAddress $IPAddress
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\ServerManager\Roles\12" -Name "ConfigurationState" -Value "2"

    New-NetIPAddress -IPAddress $IPAddress -InterfaceAlias $NIC -DefaultGateway $GateWay -AddressFamily "IPv4" -PrefixLength $PrefixLen
    Set-DnsClientServerAddress -InterfaceAlias $NIC -ServerAddresses $DNSServers

    Rename-Computer -NewName $HostName -Restart

    "2" | Out-File -FilePath $state_file
}


if((Get-Content $state_file) -eq 2)
{
    # Create System Management container and delegate access to the SCCM Server
    $SCCMHostName = "CM01"
    $root         = (Get-ADRootDSE).defaultNamingContext
    $OU           = New-ADObject -Name "System Management" -Path "CN=System, DC=homelabcoderz, DC=com" -Type "Container" -PassThru
    $ACL          = Get-Acl "ad:CN=System Management,CN=System,$root"
    $computer     = Get-ADComputer -Identity $SCCMHostName
    $SID          = [System.Security.Principal.SecurityIdentifier] $computer.SID
    $ACE          = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $SID, "GenericAll", "Allow"

    $ACL.AddAccessRule($ACE)
    Set-Acl -Path "ad:CN=System Management,CN=System,$root" -AclObject $ACL 

    "3" | Out-File -FilePath $state_file
}

if((Get-Content $state_file) -eq 3)
{
    # Extend Active Directory Schema
    $SCCMHostName = "CM01"
    & "\\$SCCMHostName\c$\Media\SCCM\SMSSETUP\BIN\X64\extadsch.exe"
    Get-Content "C:\ExtADSch.log" | Select-String "the Active Directory Schema"

    "4" | Out-File -FilePath $state_file
}

if((Get-Content $state_file) -eq 4)
{
    

    "5" | Out-File -FilePath $state_file
}


########################################
########################################

#$features = @(
#'RSAT-Role-Tools'
#'RSAT-AD-Tools',
#'RSAT-AD-PowerShell',
#'RSAT-ADLDS',
#'RSAT-ADDS',
#'RSAT-ADDS-Tools',
#'RSAT-AD-AdminCenter'
#)
#foreach($feature in $features)
#{
#install-Windowsfeature -Name $feature
#}

#New-ADOrganizationalUnit -Name "Savannah" -Path "dc=homelabcoderz,dc=com"
#$OUs = @(
#"Server",
#"Hyper-v",
#"Application",
#"AdminUsers",
#"ServiceUsers",
#"Users",
#"Group"
#)
#foreach($OU in $OUs)
#{
#New-ADOrganizationalUnit -Name $OU -Path "OU=Savannah, dc=homelabcoderz,dc=com"
#}

#New-ADGroup -Name "Admins" -SamAccountName "Admins" -GroupScope Global -GroupCategory Security -Description "Admins_Group" -Path "OU=Group, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADGroup -Name "SQL" -SamAccountName "SQL" -GroupScope Global -GroupCategory Security -Description "Admins_SQl" -Path "OU=Group, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADGroup -Name "Hyper-v" -SamAccountName "Hyper-v" -GroupScope Global -GroupCategory Security -Description "Admins_Hyper-v" -Path "OU=Group, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADGroup -Name "Application" -SamAccountName "Application" -GroupScope Global -GroupCategory Security -Description "Admins_Application" -Path "OU=Group, OU=Savannah, dc=homelabcoderz,dc=com"
    
#New-ADUser -Name "Admin" -UserPrincipalName "admin" -SamAccountName "admin" -GivenName "Admin" -Surname "IT" -DisplayName "Admin IT" -AccountPassword $pass -CannotChangePassword $false -Enabled $true -Path "OU=AdminUsers, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADUser -Name "SQL" -UserPrincipalName "admin" -SamAccountName "admin" -GivenName "Admin" -Surname "IT" -DisplayName "Admin IT" -AccountPassword $pass -CannotChangePassword $false -Enabled $true -Path "OU=AdminUsers, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADUser -Name "ADSync" -UserPrincipalName "admin" -SamAccountName "admin" -GivenName "Admin" -Surname "IT" -DisplayName "Admin IT" -AccountPassword $pass -CannotChangePassword $false -Enabled $true -Path "OU=AdminUsers, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADUser -Name "SCCMAdmin" -UserPrincipalName "admin" -SamAccountName "admin" -GivenName "Admin" -Surname "IT" -DisplayName "Admin IT" -AccountPassword $pass -CannotChangePassword $false -Enabled $true -Path "OU=AdminUsers, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADUser -Name "SCCMRemoteUser" -UserPrincipalName "admin" -SamAccountName "admin" -GivenName "Admin" -Surname "IT" -DisplayName "Admin IT" -AccountPassword $pass -CannotChangePassword $false -Enabled $true -Path "OU=AdminUsers, OU=Savannah, dc=homelabcoderz,dc=com"
#New-ADUser -Name "User" -UserPrincipalName "admin" -SamAccountName "admin" -GivenName "Admin" -Surname "IT" -DisplayName "Admin IT" -AccountPassword $pass -CannotChangePassword $false -Enabled $true -Path "OU=Users, OU=Savannah, dc=homelabcoderz,dc=com"

#Add-ADGroupMember "" admin

########################################
########################################
