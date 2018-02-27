<# 

- Save current disk info to variable
- Turn off VM 
- Unmount current disk from VM
- Save config (disk unattached)
- Create new disk from snapshot (an already existing one) - Work out how to select the correct snapshot (naming convention??)
- Mount disk
- Save VM config
- Turn on VM


Testing ISE Update on file
#>

##  Variables
$VMname = "SQL-REPLAY2"
$VMrg = "KB-AF"
$VMlocation = "North Europe"


#  Stop the VM, required when working with disks
Stop-AzureRmVM -Name $VMname -ResourceGroupName $VMrg

#  Save VM info to a variable
$VMdetails = Get-AzureRmVM -ResourceGroupName $VMrg -Name $VMname

#  Removes first data disk (LUN 0)
Remove-AzureRmVMDataDisk -VM $VMdetails -DataDiskNames $VMdetails.StorageProfile.DataDisks[0].Name

#  Update the VM state
Update-AzureRmVM -ResourceGroupName $VMrg -VM $VMdetails

#  Save snapshot of the correct disk - Matching by a hard string but you could use $VMname variable instead (depending on the naming convention used)
$snapshot = Get-AzureRmSnapshot -ResourceGroupName $VMrg | where {($_.name -match "SQL" )}


$NEWdiskconfig = New-AzureRmDiskConfig 