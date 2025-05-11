$ado_env_name=$args[0]
$ado_project_url=$args[1]
$ado_project_name=$args[2]
$ado_pat=$args[3]
$ado_work_dir="C:\ADODeploymentWorkDir"

$ErrorActionPreference="Stop";
If(-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent() ).IsInRole( [Security.Principal.WindowsBuiltInRole] "Administrator")){ throw "Run command in an administrator PowerShell prompt"};
If($PSVersionTable.PSVersion -lt (New-Object System.Version("3.0"))){ throw "The minimum version of Windows PowerShell that is required by the script (3.0) does not match the currently running version of Windows PowerShell." };
If(-NOT (Test-Path $env:SystemDrive\'azagent')){mkdir $env:SystemDrive\'azagent'}; 
cd $env:SystemDrive\'azagent'; 
for($i=1; $i -lt 100; $i++){
	$destFolder="A"+$i.ToString();if(-NOT (Test-Path ($destFolder))){mkdir $destFolder;cd $destFolder;break;}
};
$agentZip="$PWD\agent.zip";
$DefaultProxy=[System.Net.WebRequest]::DefaultWebProxy;
$securityProtocol=@();
$securityProtocol+=[Net.ServicePointManager]::SecurityProtocol;
$securityProtocol+=[Net.SecurityProtocolType]::Tls12;[Net.ServicePointManager]::SecurityProtocol=$securityProtocol;
$WebClient=New-Object Net.WebClient; 
$Uri='https://vstsagentpackage.azureedge.net/agent/4.248.0/vsts-agent-win-x64-4.248.0.zip';
if($DefaultProxy -and (-not $DefaultProxy.IsBypassed($Uri))){$WebClient.Proxy= New-Object Net.WebProxy($DefaultProxy.GetProxy($Uri).OriginalString, $True);}; 
$WebClient.DownloadFile($Uri, $agentZip);
Add-Type -AssemblyName System.IO.Compression.FileSystem;[System.IO.Compression.ZipFile]::ExtractToDirectory( $agentZip, "$PWD");
.\config.cmd --unattended --replace --environment --environmentname $ado_env_name --agent $env:COMPUTERNAME --runasservice --runAsAutoLogon --noRestart --work $ado_work_dir --url $ado_project_url --projectname $ado_project_name --auth PAT --token $ado_pat;
Remove-Item $agentZip;

# Set variables
$Username = "azureuser"
$WinRMPort = 5986
$DnsName = $env:COMPUTERNAME
$LogPath = "C:\Ansible-WinRM-Setup.log"

Start-Transcript -Path $LogPath -Append

Write-Host "Starting idempotent WinRM setup..."

if ((winrm enumerate winrm/config/listener -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host "Enabling WinRM..."
    winrm quickconfig -force
}

$basicAuth = (winrm get winrm/config/service/auth | Select-String "Basic").ToString()
if ($basicAuth -notmatch "true") {
    Write-Host "Enabling Basic Authentication..."
    winrm set winrm/config/service/auth '@{Basic="true"}'
}

$unencrypted = (winrm get winrm/config/service | Select-String "AllowUnencrypted").ToString()
if ($unencrypted -notmatch "false") {
    Write-Host "Disabling unencrypted WinRM..."
    winrm set winrm/config/service '@{AllowUnencrypted="false"}'
}

$listenerExists = winrm enumerate winrm/config/listener | Select-String "Transport = HTTPS"
if (-not $listenerExists) {
    Write-Host "Creating self-signed certificate..."
    $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation "cert:\LocalMachine\My"
    $thumbprint = $cert.Thumbprint
    Write-Host "Cert Thumbprint: $thumbprint"

    Write-Host "Creating HTTPS listener..."
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$DnsName`"; CertificateThumbprint=`"$thumbprint`"}"
} 
else {
    Write-Host "HTTPS listener already exists. Skipping..."
}

$fwRule = Get-NetFirewallRule -DisplayName "Allow WinRM over HTTPS" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    Write-Host "Adding firewall rule for port $WinRMPort..."
    New-NetFirewallRule -Name "AllowWinRMHTTPS" -DisplayName "Allow WinRM over HTTPS" `
        -Protocol TCP -LocalPort $WinRMPort -Direction Inbound -Action Allow
} else {
    Write-Host "Firewall rule already exists. Skipping..."
}

function Add-ToGroupIfMissing {
    param (
        [string]$group,
        [string]$user
    )
    $inGroup = Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $user }
    if (-not $inGroup) {
        Write-Host "Adding '$user' to '$group'..."
        Add-LocalGroupMember -Group $group -Member $user -ErrorAction SilentlyContinue
    } else {
        Write-Host "'$user' already in group '$group'. Skipping..."
    }
}

Add-ToGroupIfMissing -group "Administrators" -user $Username
Add-ToGroupIfMissing -group "Remote Management Users" -user $Username

Write-Host "Restarting WinRM service..."
Restart-Service WinRM -Force

Write-Host "Verifying WinRM listener on port $WinRMPort..."
try {
    Test-WSMan -ComputerName localhost -Port $WinRMPort -UseSSL -ErrorAction Stop
    Write-Host "WinRM over HTTPS is working."
} catch {
    Write-Warning "Test-WSMan failed: $($_.Exception.Message)"
    Write-Warning "This is expected if using a self-signed certificate. Continuing anyway..."
}

Write-Host "WinRM over HTTPS is configured and ready for Ansible."

Stop-Transcript
