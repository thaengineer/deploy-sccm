Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
Move-Item -Path "$env:TEMP\pstools\psexec.exe" .
Remove-Item -Path "$env:TEMP\pstools" -Recurse

Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True -Profile Private

# download and install msi file
$url       = ''
$file_name = ''
Invoke-WebRequest -Uri $url -OutFile ".\$file_name"
Start-Process -FilePath "msiexec.exe" -ArgumentList "/i $file_name /qb /norestart"
