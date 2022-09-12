$StateFile = "C:\Temp\state.txt"
$DomainName = "homelabcoderz.com"
$pass       = ConvertTo-SecureString "Password?123" -AsPlainText -Force
$ADDSHostName = "DC01"
$SCCMHostName = "CM01"


# ((Get-WindowsFeature) | where { $_.InstallState -eq 'Installed' })


if(! (Test-Path -Path "C:\Temp"))
{
    New-Item -Path "C:\" -Name "Temp" -ItemType Directory | Out-Null
    if(! (Test-Path -Path "C:\Temp\state.txt"))
    {
        New-Item -Path "C:\Temp" -Name "state.txt" -ItemType File | Out-Null
        "0" | OutFile -FilePath $StateFile
    }
}


if((Get-Content $StateFile) -eq 0)
{
    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [Active Directory Domain Services]"
    Install-WindowsFeature -name "AD-Domain-Services" -IncludeManagementTools

    Install-ADDSForest -DomainName "homelabcoderz.com" -SafeModeAdministratorPassword $pass -CreateDnsDelegation:$false -DatabasePath "C:\Windows\NTDS" -DomainMode "Win2012R2" -DomainNetbiosName "HOMELABCODERZ" -ForestMode "Win2012R2" -InstallDns:$true -LogPath "C:\Windows\NTDS" -NoRebootOnCompletion:$true -SysvolPath "C:\Windows\SYSVOL" -Force:$true -Verbose

    "1" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 1)
{
    $NIC         = (Get-NetAdapter).Name
    $IPAddress   = "192.168.160.2"
    $NetMask     = "255.255.255.0"
    $PrefixLen   = 24
    $GateWay     = "192.168.160.1"
    $DNSServers = ("1.1.1.1", "1.0.0.1")

    Write-Host "installing: [$(Get-Date -Format "HH:mm:ss")] [DHCP]"
    Install-WindowsFeature -name "DHCP" -IncludeManagementTools

    Add-DhcpServerv4Scope -Name "Scope" -StartRange "192.168.160.2" -EndRange "192.168.160.200" -SubnetMask $NetMask -LeaseDuration 8.00:00:00
    Add-DhcpServerInDC -DnsName $ADDSHostName.$DomainName -IPAddress $IPAddress
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12" -Name "ConfigurationState" -Value "2"

    New-NetIPAddress -IPAddress $IPAddress -InterfaceAlias $NIC -DefaultGateway $GateWay -AddressFamily "IPv4" -PrefixLength $PrefixLen
    Set-DnsClientServerAddress -InterfaceAlias $NIC -ServerAddresses $DNSServers

    Rename-Computer -NewName $ADDSHostName

    "2" | Out-File -FilePath $StateFile

    Restart-Computer
}


if((Get-Content $StateFile) -eq 2)
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

    "3" | Out-File -FilePath $StateFile
}


if((Get-Content $StateFile) -eq 3)
{
    # Extend Active Directory Schema
    $SCCMHostName = "CM01"

    if(! (Test-Path -Path "\\$SCCMHostName\c$"))
    {
        Write-Host "error: path to $SCCMHostName not found"
        exit(1)
    }
    else
    {
        & "\\$SCCMHostName\c$\Media\SCCM\SMSSETUP\BIN\X64\extadsch.exe"
        Get-Content "C:\ExtADSch.log" | Select-String "the Active Directory Schema"

        "4" | Out-File -FilePath $StateFile
    }
}

if((Get-Content $StateFile) -eq 4)
{
    $OrgUnits = @(
        "Groups",
        "Users",
        "ServiceUsers"
    )
    $DomainAdmins = @(
        "admins",
        "sqladmins",
        "sccmadmins"
    )

    Write-Host "working: [$(Get-Date -Format "HH:mm:ss")] [Creating OUs, Groups and Users]"
    New-ADOrganizationalUnit -Name "Savannah" -Path "DC=homelabcoderz, DC=com"

    foreach($OrgUnit in $OrgUnits)
    {
        New-ADOrganizationalUnit -Name $OrgUnit -Path "OU=Savannah, DC=homelabcoderz, DC=com"
    }

    New-ADGroup -Name "Admins" -SamAccountName "admins" -DisplayName "Savannah Admins" -Description "Savannah Admins" -GroupCategory "Security" -GroupScope "Global" -Path "OU=Groups, OU=Savannah, DC=homelabcoderz, DC=com"
    New-ADGroup -Name "SQLAdmins" -SamAccountName "sqladmins" -DisplayName "Savannah SQL Admins" -Description "Savannah SQL Admins" -GroupCategory "Security" -GroupScope "Global" -Path "OU=Groups, OU=Savannah, DC=homelabcoderz, DC=com"
    New-ADGroup -Name "SCCMAdmins" -SamAccountName "sccmadmins" -DisplayName "Savannah SCCM Admins" -Description "Savannah SCCM Admins" -GroupCategory "Security" -GroupScope "Global" -Path "OU=Groups, OU=Savannah, DC=homelabcoderz, DC=com"

    New-ADUser -Name "Admin" -SamAccountName "admin" -UserPrincipalName "admin" -GivenName "IT" -Surname "Admin" -DisplayName "Admin" -AccountPassword $pass -Path "OU=Users, OU=Savannah, DC=homelabcoderz, DC=com" -ChangePasswordAtLogon $false -CannotChangePassword $false -PasswordNeverExpires $true -Enabled $true
    New-ADUser -Name "SQLAdmin" -SamAccountName "sqladmin" -UserPrincipalName "sqladmin" -GivenName "SQL" -Surname "Admin" -DisplayName "SQL Admin" -AccountPassword $pass -Path "OU=Users, OU=Savannah, DC=homelabcoderz, DC=com" -ChangePasswordAtLogon $false -CannotChangePassword $false -PasswordNeverExpires $true -Enabled $true
    New-ADUser -Name "ADSync" -SamAccountName "adsync" -UserPrincipalName "adsync" -GivenName "ADSync" -Surname "Admin" -DisplayName "AD Sync Admin" -AccountPassword $pass -Path "OU=Users, OU=Savannah, DC=homelabcoderz, DC=com" -ChangePasswordAtLogon $false -CannotChangePassword $false -PasswordNeverExpires $true -Enabled $true
    New-ADUser -Name "SCCMAdmin" -SamAccountName "sccmadmin" -UserPrincipalName "sccmadmin" -GivenName "SCCM" -Surname "Admin" -DisplayName "SCCM Admin" -AccountPassword $pass -Path "OU=Users, OU=Savannah, DC=homelabcoderz, DC=com" -ChangePasswordAtLogon $false -CannotChangePassword $false -PasswordNeverExpires $true -Enabled $true
    New-ADUser -Name "SCCMRemoteUser" -SamAccountName "sccmremoteuser" -UserPrincipalName "sccmremoteuser" -GivenName "SCCMRemote" -Surname "Admin" -DisplayName "SCCM Remote Admin" -AccountPassword $pass -Path "OU=Users, OU=Savannah, DC=homelabcoderz, DC=com" -ChangePasswordAtLogon $false -CannotChangePassword $false -PasswordNeverExpires $true -Enabled $true
    New-ADUser -Name "Test" -SamAccountName "test" -UserPrincipalName "test" -GivenName "Test" -Surname "User" -DisplayName "Test User" -AccountPassword $pass -Path "OU=Users, OU=Savannah, DC=homelabcoderz, DC=com" -ChangePasswordAtLogon $false -CannotChangePassword $false -PasswordNeverExpires $true -Enabled $true

    foreach($DomainAdmin in $DomainAdmins)
    {
        Add-ADGroupMember -Identity "Domain Admins" -Members $DomainAdmin
    }

    Add-ADGroupMember -Identity "admins" -Members "admin"
    Add-ADGroupMember -Identity "sqladmins" -Members "sqladmin"
    Add-ADGroupMember -Identity "sccmadmins" -Members "adsync"
    Add-ADGroupMember -Identity "sccmadmins" -Members "sccmadmin"
    Add-ADGroupMember -Identity "sccmadmins" -Members "sccmremoteuser"

    Remove-Item -Path $StateFile | Out-Null

    Write-Host "completed: [$(Get-Date -Format "HH:mm:ss")]"
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

########################################
########################################
