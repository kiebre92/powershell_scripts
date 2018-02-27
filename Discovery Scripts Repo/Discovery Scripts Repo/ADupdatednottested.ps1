<# Requires Import-Module ActiveDirectory to use Get-ADComputer
#To import module execute 'Import-Module servermanager'
#Then execute 'Add-WindowsFeature RSAT'
#Then execute 'Import-Module ActiveDirectory'

cFor properties that can be discovered see http://social.technet.microsoft.com/wiki/contents/articles/12056.active-directory-get-adcomputer-default-and-extended-properties.aspx
#>

Import-Module ActiveDirectory

# Only thing to change here is the out-file path location
Get-ADComputer -Filter * -Property * -ResultPageSize 5 | Select-Object DNSHostName,<#OperatingSystem,Enabled,OperatingSystemServicePack,#>IPv4Address | Out-file  "C:\Users\Administrator.SHAPING-CLOUD\Desktop\Outputs\ADQuerydata.tom" # | ConvertTo-JSON  |  Out-file  "C:\Users\Administrator.SHAPING-CLOUD\Desktop\Ouputs\ADQuerydata.JSON"

$adobjects = Get-ADComputer -Filter * -Properties IPv4Address, OperatingSystem, OperatingSystemServicePack

$adobjects | Select-object DNSHostname,IPv4Address, OperatingSystem, OperatingSystemServicePack | ConvertTo-Json | Out-File "C:\Users\Administrator.SHAPING-CLOUD\Desktop\Outputs\ADQuerydata.JSON"







