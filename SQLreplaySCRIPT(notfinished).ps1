# https://docs.microsoft.com/en-us/azure/virtual-machines/windows/powershell-samples

# Sub ID: 8caab2f8-d3f5-47cc-aa5c-03f40f47a7cd

# Set-AzureRmContext -Subscription 850fe357-eec7-4a0b-beb0-535251d28dfd

$resourceGroup = "KB-AF"
$location = "NorthEurope"
$VMSize = "Standard_A1_v2"

$cred = Get-Credential -Message "Enter local admin username/password for the VM."
$vnet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroup -Name "PROD-VNET"

# $RULEallowRDPtoVM = New-AzureRmNetworkSecurityRuleConfig -Name AllowRDPonPremINbound -Protocol TCP -Direction Inbound -Priority 100 -SourceAddressPrefix * `
# -DestinationAddressPrefix * -DestinationPortRange 3389 -Access Allow

For($num=1; $num -le 1; $num++)
{
$vmName = "SQL-REPLAY$num"
write-host $vmName
$nic = New-AzureRmNetworkInterface -Name "$vmname-NIC" -ResourceGroupName $resourceGroup -Location $location -SubnetId $vnet.Subnets[0].Id 

$vmConfig = New-AzureRmVMConfig -VMName $vmname -VMSize $VMSize | ` 
Set-AzureRmVMOperatingSystem -Windows -ComputerName $vmName -Credential $cred | `
Set-AzureRmVMSourceImage -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2012-R2-Datacenter" -Version latest | `
Add-AzureRmVMNetworkInterface -Id $nic.Id
## Need to add storage parameters, Offer needs changing? all other KB bits needs changing to correct

New-AzureRmVM -ResourceGroupName $resourceGroup -Location $location -VM $vmConfig

}
