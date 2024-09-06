<# Examples:
%comspec% /b /cl start /b /min powershell -nop -w hidden -encodedcommand ZgByAGEAYwBhAHMAbgBlAGcAbABpAGcAZQBuAHQAcwBwAGwAZQBuAGUAdABpAGMAcgB1AGYAZgBpAGEAbgA=
%windir%\R5sLXSuKf.exe
rundll32.exe C:\Users\<random>\AppData\Local\Temp\LYwsGF9ehrvd5.dll
cmd.exe /C start %COMSPEC% /C 'timeout /t 3 >nul&&echo ikrqD \\.\pipe\ikrqD'
cmd.exe /c 'echo ikrqD > \\.\pipe\ikrqD'
\\127.0.0.1\$ADMIN\91kNx.exe
#>

function Get-RandomPrivateIPAddress {
    # Define the private IP address ranges
    $ranges = @(
        @{ Base = "10."; Octet2Range = 0..255; Octet3Range = 0..255; Octet4Range = 1..254 },
        @{ Base = "172."; Octet2Range = 16..31; Octet3Range = 0..255; Octet4Range = 1..254 },
        @{ Base = "192.168."; Octet3Range = 0..255; Octet4Range = 1..254 }
    )
    
    # Select a random range
    $range = Get-Random -InputObject $ranges
    
    # Ensure the selected range is not null or empty
    if ($range -eq $null) {
        Write-Error "No valid range selected."
        return
    }

    # Generate random octets within the selected range
    $octet1 = $range.Base
    $octet2 = if ($range.ContainsKey("Octet2Range")) { Get-Random -InputObject $range.Octet2Range } else { "" }
    $octet3 = Get-Random -InputObject $range.Octet3Range
    $octet4 = Get-Random -InputObject $range.Octet4Range

    # Ensure none of the octets are empty
    if ($octet1 -eq $null -or $octet3 -eq $null -or $octet4 -eq $null -or ($octet2 -eq $null -and $range.ContainsKey("Octet2Range"))) {
        Write-Error "Failed to generate a valid IP address."
        return
    }

    # Format the IP address
    if ($range.Base -eq "192.168.") {
        return -join "$octet1$octet3.$octet4"
    } else {
        return -join "$octet1$octet2.$octet3.$octet4"
    }
}

function CreateService 
{
        param ([string]$svcexe,[string]$svcname)
        write-host $svcname $svcexe
        & c:\windows\system32\sc.exe create $svcname binPath= "$svcexe" type= own
        start-sleep -Seconds 2
        & c:\windows\system32\sc.exe delete $svcname
}

function powershell_service
{
    $ps_template1 = "%comspec% /b /c start /b /min powershell -nop -w hidden -encodedcommand '<random>'"
    $ps_template2 = "powershell -nop -w hidden -noni -c '$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(`"<random>`"))IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();'"
    $ps_templates = @($ps_template1,$ps_template2)
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    

    foreach($template in $ps_templates)
    {
        $randomLength = Get-Random -Minimum 30 -Maximum 201
        $randomString = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($randomString)
        $randomb64 =[Convert]::ToBase64String($Bytes)

        $servicebin = $template.replace("<random>",$randomb64)
        
        $randomLength = Get-Random -Minimum 6 -Maximum 10
        $randomString = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        CreateService -svcexe $servicebin -svcname $randomString
               
    }

    

}

function rundll32_service
{
    $names = get-content .\names.txt
    $rundll_template1 = "rundll32.exe C:\Users\<randomname>\AppData\Local\Temp\<random>.dll,StartW"
    $rundll_template2 = "rundll32.exe %windir%\<random>.dll,StartW"
    $rundll_template3 = "rundll32.exe %programdata\<random>.dll,DllMain"
    $rundll_template4 = "rundll32.exe %public%\<random>.dll,StartW"
    $rundll_templates = @($rundll_template1,$rundll_template2,$rundll_template3,$rundll_template4)
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    
    foreach($template in $rundll_templates)
    {
  
        if($template -like "*AppData*")
        {
            $username = ((Get-Random -InputObject $names -Count 1) + "." +(Get-Random -InputObject $names -Count 1)).ToString()
            $template = $template.replace("<randomname>",$username)
        }
        $randomLength = Get-Random -Minimum 6 -Maximum 12
        $randomString = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        $servicebin = $template.replace("<random>",$randomString)

        #& c:\windows\system32\sc.exe create $randomString binPath= "$servicebin" type= own
        #start-sleep -Seconds 2
        #& c:\windows\system32\sc.exe delete $randomString
        CreateService -svcexe $servicebin -svcname $randomString
               
    }
}

function adminshare_service
{
    $adminshare_template1 = "\\127.0.0.1\<randomshare>\<random>.exe"
    $adminshare_template2 = "\\localhost\<randomshare>\<random>.exe"
    $adminshare_template3 = "\\<randomip>\<randomshare>\<random>.exe"
    $adminshare_templates = @($adminshare_template1,$adminshare_template2,$adminshare_template3)
    $adminshares= @("`$ADMIN","C$","IPC$")
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    
    
    foreach ($template in $adminshare_templates)
    {
        if($template -like "*<randomip>*")
        {
            [string]$randomIP = Get-RandomPrivateIPAddress
            $template = $template.Replace("<randomip>",$randomIP)  
        }

        [string]$randomshare = $adminshares[(Get-Random -Minimum 0 -Maximum 2)]
        $template = $template.replace("<randomshare>",$randomshare)
        $randomLength = Get-Random -Minimum 6 -Maximum 12
        $randomString = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        $servicebin = $template.replace("<random>",$randomString)
        
        #& c:\windows\system32\sc.exe create $randomString binPath= "$servicebin" type= own
        #start-sleep -Seconds 2
        #& c:\windows\system32\sc.exe delete $randomString
        CreateService -svcexe $servicebin -svcname $randomString
    }
}

function namedpipe_service
{
    $namedpipe_template1 = "cmd.exe /C start %COMSPEC% /C 'timeout /t 3 >nul&&echo <random> \\.\pipe\<random>'"
    $namedpipe_template2 = "cmd.exe /c 'echo <random> > \\.\pipe\<random>'"
    $namedpipe_template3 = "cmd.exe /c 'echo <randomname> > \\.\pipe\<random>'"
    $namedpipe_templates= @($namedpipe_template1,$namedpipe_template2,$namedpipe_template3)
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    foreach($template in $namedpipe_templates)
    {
        
        if($template -like "*<randomname>*")
        {
             $randomLength = Get-Random -Minimum 6 -Maximum 8
             $servicename = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
             $template = $template.Replace("<randomname>",$servicename)
        }

        $randomLength = Get-Random -Minimum 6 -Maximum 8
        $randomString = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        $servicebin = $template.replace("<random>",$randomString)
        
        #& c:\windows\system32\sc.exe create $randomString binPath= "$servicebin" type= own
        #start-sleep -Seconds 2
        #& c:\windows\system32\sc.exe delete $randomString

        CreateService -svcexe $servicebin -svcname $randomString
     }
}

function windir_service
{
    $windir_template1 = "%windir%\<random>.exe"
    $windir_template2 = "%programdata\<random>.exe"
    $windir_template3 = "%public%\<random>.exe"
    $windir_templates= @($windir_template1,$windir_template2,$windir_template3)
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    foreach($template in $windir_templates)
    {
        $randomLength = Get-Random -Minimum 6 -Maximum 8
        $randomservicename = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        $randomLength = Get-Random -Minimum 6 -Maximum 8
        $randomString = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
        $servicebin = $template.replace("<random>",$randomString)
        #echo $servicebin
       # & c:\windows\system32\sc.exe create $randomservicename binPath= "$servicebin" type= own
       # start-sleep -Seconds 2
       # & c:\windows\system32\sc.exe delete $randomservicename
       CreateService -svcexe $servicebin -svcname $randomString
    }
}

function rmm_service
{
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    
    $psexec_name = "PSEXESVC"
    $psexec_template = "%SytemRoot%\PSEXESVC.exe"
    #& c:\windows\system32\sc.exe create $psexec_name binPath= "$psexec_template" type= own
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe delete $psexec_name
    CreateService -svcexe $psexec_template -svcname $psexec_name
    
    $sc_name = "ScreenConnect Client (<randomname>)"
    $randomLength = Get-Random -Minimum 14 -Maximum 16
    $randomname = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    $servicename = $sc_name.Replace("<randomname>",$randomname)
    $sc_template1 = "'C:\Program Files (x86)\ScreenConnect Client (<randomname>)\ScreenConnect.ClientService.exe'"
    $servicebin = $sc_template1.replace("<randomname>",$randomname)
    #write-host $servicebin
    #& c:\windows\system32\sc.exe create $servicename binPath= "$servicebin" type= own
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe delete $servicename
    CreateService -svcexe $servicebin -svcname $servicename
    
    $sc_template2 = "C:\Users\<randomuser>\AppData\Local\Apps\2.0\<randompath>\ScreenConnect.ClientService.exe `"?e=Support&y=Guest&h=instance-<randomdomain>.screenconnect.com&p=443&s=<guid>&k=<randomkey>%20Axline`" `"1`""
    $names = get-content .\names.txt
    $username = ((Get-Random -InputObject $names -Count 1) + "." +(Get-Random -InputObject $names -Count 1)).ToString()
    $servicebin = $sc_template2.Replace("<randomuser>",$username)
    $randomLength = Get-Random -Minimum 6 -Maximum 9
    $randompath = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    $servicebin = $servicebin.Replace("<randompath>",$randompath)
    $randomLength = Get-Random -Minimum 3 -Maximum 6
    $randomdomain = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    $servicebin = $servicebin.Replace("<randomdomain>",$randomdomain)
    $guid = new-guid
    $servicebin = $servicebin.Replace("<guid>",$guid)
    $randomLength = Get-Random -Minimum 30 -Maximum 50
    $randomkey = -join ((1..$randomLength) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })
    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($randomkey)
    $randomkey =[Convert]::ToBase64String($Bytes)
    $servicebin = $servicebin.Replace("<randomkey>",$randomkey)
    #write-host $servicebin
    #& c:\windows\system32\sc.exe create $sc_name binPath= "$servicebin" type= own
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe delete $sc_name
    CreateService -svcexe $servicebin -svcname $servicename
    
    $splashtop_name = "SplashtopRemoteService"
    $splashtop = "C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\SRManager.exe"
    #& c:\windows\system32\sc.exe create $splashtop_name binPath= "$splashtop" type= own
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe delete $splashtop_name
    CreateService -svcexe $splashtop -svcname $splashtop_name
    
    $teamviewer_name = "TeamViewer"
    $teamviewer_template1 = "C:\Program Files\TeamViewer\TeamViewer_Service.exe"
    $teamviewer_template2 = "C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe"
    CreateService -svcexe $teamviewer_template1 -svcname $teamviewer_name
    CreateService -svcexe $teamviewer_template2 -svcname $teamviewer_name
    #& c:\windows\system32\sc.exe create $teamviewer_name binPath= "$teamviewer_template1" type= own
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe delete $teamviewer_name
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe create $teamviewer_name binPath= "$teamviewer_template2" type= own
    #start-sleep -Seconds 2
    #& c:\windows\system32\sc.exe delete $teamviewer_name
    
    $anydesk_name = "AnyDesk"
    $anydesk_template = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
    CreateService -svcexe $anydesk_template -svcname $anydesk_name
}

for ($i = 1; $i -le 100; $i++)
{
powershell_service
rundll32_service
adminshare_service
namedpipe_service
windir_service
rmm_service
}