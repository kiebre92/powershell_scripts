$KeyVaultName = "SCMPoCKeyVault"
$KVrgName = "FUNCTIONAL"

 

$vmName = Read-Host "Enter Server name"

$app = Get-AzureRmADApplication -IdentifierUri "https://gmhsc.org/69629df3-a77c-4142-8094-c8d438480214"

 

$Password = "Vubo4824"

 

$keyVault = Get-AzureRmKeyVault -VaultName $keyVaultName -ResourceGroupName $KVrgName;

$diskEncryptionKeyVaultUrl = $keyVault.VaultUri;

$keyVaultResourceId = $keyVault.ResourceId;

$keyEncryptionKeyUrl = (Get-AzureKeyVaultKey -VaultName $keyVaultName -Name "SCMPoCKey1").Key.kid;


$VMrgName = "RIGHTSIZE"

$sequenceVersion = [Guid]::NewGuid();

#Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $VMrgName -VMName $vmName  -AadClientID $app.ApplicationId.Guid  -AadClientSecret $Password  -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl  -DiskEncryptionKeyVaultId $keyVaultResourceId -KeyEncryptionKeyUrl $keyEncryptionKeyUrl  -KeyEncryptionKeyVaultId $keyVaultResourceId

Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $VMrgname -VMName $vmName -AadClientID $app.ApplicationId.Guid -AadClientSecret $Password -DiskEncryptionKeyVaultUrl $diskEncryptionKeyVaultUrl -DiskEncryptionKeyVaultId $KeyVaultResourceId -KeyEncryptionKeyUrl $keyEncryptionKeyUrl -KeyEncryptionKeyVaultId $KeyVaultResourceId –SequenceVersion $sequenceVersion