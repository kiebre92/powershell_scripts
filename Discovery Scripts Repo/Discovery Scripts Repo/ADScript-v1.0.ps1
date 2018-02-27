<# Requires Import-Module ActiveDirectory to use Get-ADComputer
#To import module execute 'Import-Module servermanager'
#Then execute 'Add-WindowsFeature RSAT'
#Then execute 'Import-Module ActiveDirectory'

#For properties that can be discovered see http://social.technet.microsoft.com/wiki/contents/articles/12056.active-directory-get-adcomputer-default-and-extended-properties.aspx
#>

Import-Module ActiveDirectory

# Only thing to change here is the out-file path location
Get-ADComputer -Filter * -Property * | Select-Object DNSHostName,OperatingSystem,Enabled,OperatingSystemServicePack,IPv4Address | ConvertTo-JSON |  Out-file  "C:\Users\Administrator.SHAPING-CLOUD\Desktop\Ouputs\ADQuerydata.JSON"