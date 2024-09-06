Function Get-HuntingLogs
{
    $HuntLogOut = @()
    #High Value Hunting Event Logs
    Write-Host "Collecting High Value Event Logs. This could take a while"
    Write-Host "Collection System Hunting Logs"
    $SysHuntLog = Get-EventLog 'System'  -ErrorAction SilentlyContinue | where {$_.EventID -eq 7045} 
    if($SysHuntLog)
    {
        foreach($x in $SysHuntLog)
        {
        $FileNameRex = [regex]::Match($x.Message, 'Service File Name:\s+(.*)')
        $serviceFileName=$FileNameRex.Groups[1].Value
        $ServiceNameRex = [regex]::Match($x.Message, 'Service Name:\s+(.*)')
        $serviceName=$ServiceNameRex.Groups[1].Value
        $EventID = $x.EventID
        $UserName = $x.UserName
        $ServiceTypeRex = [regex]::Match($x.Message, 'Service Type:\s+(.*)')
        $ServiceType = $ServiceTypeRex.Groups[1].Value
        $ServiceStartTypeRex = [regex]::Match($x.Message, 'Service Start Type:\s+(.*)')
        $ServiceStartType = $ServiceStartTypeRex.Groups[1].Value
        $TimeStamp = ([datetime]$x.TimeGenerated.ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $ID = [guid]::NewGuid()

        if ($ServiceName -match 'psexecsvc|anydesk|teamviewer|screenconnect|splashtop') 
        {
            $Label = "suspicious"
        }
        else
        {
            $Label = "malicious"
        }

        $HuntingLogObject = new-object psobject
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Timestamp" -Value $TimeStamp
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Event ID" -Value $EventID
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "ID" -Value $ID
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Account_Name" -Value "LocalSystem"
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Service File Name" -Value $serviceFileName
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Service Name" -Value $serviceName
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Service Type" -Value $ServiceType
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Service Start Type" -Value $ServiceStartType
        $HuntingLogObject | Add-Member -MemberType NoteProperty -Name "Label" -Value $Label
        $HuntLogOut += $HuntingLogObject
        }
    }
   
    $HuntLogOut | Export-Csv -NoTypeInformation $CollectionPath/WindowsHuntingLogs.csv
    
    #End High Value Hunting Event Logs
}

$CollectionPath =".\" + $ENV:COMPUTERNAME + "_" + (Get-Date).tostring("yyyyMMdd")
New-Item $CollectionPath -Type Directory -Force
##Version Check

Get-HuntingLogs
