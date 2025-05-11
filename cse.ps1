$ado_env_name=$args[0]
$ado_project_url=$args[1]
$ado_project_name=$args[2]
$ado_pat=$args[3]
$ado_work_dir="C:\ADODeploymentWorkDir"

winrm quickconfig -force
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="false"}'

$cert = New-SelfSignedCertificate -DnsName "$env:COMPUTERNAME" -CertStoreLocation "cert:\LocalMachine\My"
$thumbprint = $cert.Thumbprint
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname='$env:COMPUTERNAME'; CertificateThumbprint='$thumbprint'}"

New-NetFirewallRule -Name "AllowWinRMHTTPS" -Protocol TCP -LocalPort 5986 -Direction Inbound -Action Allow

Set-Service -Name WinRM -StartupType Automatic
Start-Service WinRM

Add-LocalGroupMember -Group "Administrators" -Member "azureuser"
Add-LocalGroupMember -Group "Remote Management Users" -Member "azureuser"

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
