$Server=”192.168.1.210”           
[System.Reflection.Assembly]::LoadWithPartialName(“Microsoft.SqlServer.SMO”) | out-null

$SMOserver = New-Object (‘Microsoft.SqlServer.Management.Smo.Server’) -argumentlist $Server

## This is the sql connections portion of the script
$fqdn = ([system.net.dns]::GetHostentry($Server).hostname)
$dns = $fqdn.Split(".")[0]
try {

        $output = Invoke-Sqlcmd -ServerInstance $Server 'sp_who' | Where {$_.hostname -inotmatch "$dns" -and $_.dbname -inotmatch "master" -and ($_.dbname -ne "null") } | Select-Object spid, ecid, status, loginame, hostname, blk, dbname, cmd, request_id
        $output
        $output | ConvertTo-Json | Out-file -FilePath "C:\Users\Administrator.SHAPING-CLOUD\Desktop\Discovery Script Development\SQL Outputs\DBConnections$server.json"
    }

Catch
    {
        Write-Host "No Hostname Found for $server"
        Write-Host ($Error[0].Exception)

    }
####################################

$ds = @()

# These need further work doing on the formatting
foreach($d in $SMOserver.Databases){
    $ds += @{
        DBName = $d.Name
        DBsize = ($d.FileGroups[0].Size / 1KB)
        SpaceAvailable = ($d.SpaceAvailable / 1KB)
        Files = $d.FileGroups[0].Files[0].FileName

        LogName = $d.LogFiles[0].Name
        LogLocation = $d.LogFiles[0].FileName
        LogSize = ($d.LogFiles[0].Size / 1KB)
        LogUsed = ($d.LogFiles[0].UsedSpace / 1KB)
        TotalSize = $d.Size
        
    }
}

$ds  | ConvertTo-Json | Out-file -FilePath "C:\Users\Administrator.SHAPING-CLOUD\Desktop\Discovery Script Development\SQL Outputs\Databases$server.json"




