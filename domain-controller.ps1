$ADDCFeatures = Get-Content -Path '.\dsdc-features.txt'

Write-Host "Installing required features for DC..."

foreach($feature in $ADDCFeatures)
{
    if((Get-WindowsFeature -Name "$feature").InstallState -ne 'Installed')
    {
        Install-WindowsFeature -Name "$feature"
    }
}

# Create System Management container and delegate access to SCCMVM
New-ADObject -Name "System Management" -Path "CN=System, DC=homelabcoderz, DC=com" -Type "Container"

# Extend Active Directory Schema
& "\\sccmvm\c$\Media\SCCM\SMSSETUP\BIN\X64\extadsch.exe"
Get-Content "C:\ExtADSch.log" | Select-String "the Active Directory Schema"