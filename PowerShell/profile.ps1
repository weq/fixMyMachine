If($host.Name -eq 'ConsoleHost') {import-module PSReadline,Pansies,Posh-Git}

# Change Window Title
[System.Security.Principal.WindowsPrincipal]$global:currentUser =
New-Object System.Security.Principal.WindowsPrincipal(
[System.Security.Principal.WindowsIdentity]::GetCurrent()
)
if($global:currentUser.IsInRole(
[System.Security.Principal.WindowsBuiltInRole]::Administrator)
) {
  $user = $global:currentUser.Identities.Name + " (Administrator)";
} else {
  $user = $global:currentUser.Identities.Name
}
(Get-Host).UI.RawUI.WindowTitle =  $user + " $(New-Text "&#10084;") PS @ " + [System.Net.Dns]::GetHostName() + " (v" + (Get-Host).Version + ")";

# Change the Prompt


# Load posh-git example profile
# . 'H:\Git\posh-git\profile.example.ps1'

$Global:line = 0
function Prompt {
    # Print number of Commands entered
    Write-Host ("[") -NoNewline -ForegroundColor DarkGray
    Write-Host ($Global:line) -NoNewline -ForegroundColor Green
    Write-Host ("] ") -NoNewline -ForegroundColor DarkGray
    Write-Host ("[") -NoNewline -ForegroundColor DarkGray
    Write-Host "I $(New-Text "&hearts;" -fg "DarkRed") PS" -NoNewline
    Write-Host ("] ") -NoNewline -ForegroundColor DarkGray
    Write-Host ("[ ") -NoNewline -ForegroundColor DarkGray
    $Global:line += 1
    $origLastExitCode = $LASTEXITCODE
    Write-Host $ExecutionContext.SessionState.Path.CurrentLocation -NoNewline
    Write-Host (" | ") -nonewline -foregroundcolor DarkGray
    Write-Host ((Get-Childitem $PWD).Length + " ") -nonewline -foregroundcolor Yellow
    Write-Host (" ]") -NoNewline -ForegroundColor DarkGray
    Write-VcsStatus
    $LASTEXITCODE = $origLastExitCode
    "$(' >' * ($nestedPromptLevel + 1)) "
}

# Create own supportive functions
Function ml {Set-Location -Path C:\Midlertidig_Lagring}
Function devfolder {Set-Location -Path W:\DEV\NYYO\git}
Function Get-ADUserWithMemberOf
{
    [CmdletBinding()]
	Param
	(
        [Parameter(Mandatory=$true,
                    ValueFromPipelineByPropertyName=$true,
                    ValueFromPipeline=$true,
                    Position=0
        )]
        [String]$Identity
	)	
    Process
    {
        ForEach ($User in $Identity)
        {
            Get-ADUser -Identity $User -Properties MemberOf
        }
    }
}

Function Find-ADGroup
{
    Param
    (
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true
        )]
        [String[]]$GroupWildcard
    )
    Process
    {
        ForEach ($Group in $GroupWildcard)
        {
            Get-ADGroup -Filter {Name -like $Group}
        }
    }
}

Function Get-HVIServer
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Position=0)]
        [string]$computerName,

        [Switch]$all
    )

    if ($all -eq $true) {
        Get-ADComputer -Filter * -SearchBase "OU=Servere,OU=Maskiner,DC=ihelse,DC=net"
    } else {
        Get-ADComputer -Filter {Name -like $computerName} -Searchbase "OU=Servere,OU=Maskiner,DC=ihelse,DC=net"
    }
}

Function Get-HVIComputer
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Position=0)]
        [string]$computerName,

        [Switch]$all
    )

    if ($all -eq $true) {
        Get-ADComputer -Filter * -SearchBase "OU=IHN Klienter,OU=Workstation,OU=Maskiner,DC=ihelse,DC=net"
    } else {
        Get-ADComputer -Filter {Name -like $computerName} -SearchBase "OU=IHN Klienter,OU=Workstation,OU=Maskiner,DC=ihelse,DC=net"
    }
}

function Get-ADUserLastLogon {
    [CmdletBinding()]
    param($username)

    $allDC = (Get-ADForest).Domains | ForEach-Object { Get-ADDomainController -Filter * -Server $_ }
    $lastLogon = @()
    foreach($dc in $allDC) {
        $user = Get-ADUser $userName -Server $dc.HostName -Properties lastLogontimestamp
        $lastLogon += $user
    }
    ([DateTime]($lastLogon | Sort-Object -Descending lastLogontimestamp)[0].lastLogontimestamp).AddYears(1600).ToLocalTime()
}
function Get-ADUserPwdLastSet {
    [CmdletBinding()]
    param($username)

    $allDC = (Get-ADForest).Domains | ForEach-Object { Get-ADDomainController -Filter * -Server $_ }
    $pwdLastSet = @()
    foreach($dc in $allDC) {
        $user = Get-ADUser $userName -Server $dc.HostName -Properties pwdLastSet
        $pwdLastSet += $user
    }
    ([DateTime]($pwdLastSet | Sort-Object -Descending pwdLastSet)[0].pwdLastSet).AddYears(1600).ToLocalTime()
}
function Get-ADUserPWDExpiryDate {
    [CmdletBinding()]
    param($username)

    $allDC = (Get-ADForest).Domains | Foreach-Object { Get-ADDomainController -Filter * -Server $_}
    $pwdExpiryDate = @()
    foreach($dc in $allDC) {
        $user = Get-ADUser $username -Server $dc.HostName -Properties "msDS-UserPasswordExpiryTimeComputed"
        $pwdExpiryDate += $user
    }
    ([DateTime]::FromFileTime(($pwdExpiryDate | Sort-Object -Descending msDS-UserPasswordExpiryTimeComputed)[0]."msDS-UserPasswordExpiryTimeComputed"))
}

Function Start-Adm-Putty {
    Start-Process -FilePath "C:\Program Files (x86)\PuTTY\putty.exe" -credential "hs\adm_nyyo" -workingdirectory "C:\Program Files (x86)\PuTTY\"
}

Function Start-Adm-Hubot {
    Start-Process -FilePath "C:\Program Files (x86)\PuTTY\putty.exe" -credential "hs\adm_nyyo" -argumentlist "-load vir-app5207.ipa.ihelse.net" -workingdirectory "C:\Program Files (x86)\PuTTY\"
}

Function Start-Adm-Hubot-WinSCP {
    Start-Process -FilePath "C:\Program Files (x86)\WinSCP\WinSCP.exe" -credential "hs\adm_nyyo"
}

Function Send-TorrentFiles {
    [CmdletBinding()]
    param()
    Set-Location "$($env:USERPROFILE)\Downloads"
    get-childitem *.torrent | Compress-Archive -DestinationPath $($env:temp + "\torrent.zip")
    Send-MailMessage -Attachments $env:temp\torrent.zip -From nyyo@ihelse.net -To nyyo@ihelse.net,weq+zip@weq.no -SmtpServer smtp.ihelse.net -Subject "IS: Torrent file"
    Remove-item $env:temp\torrent.zip
    Remove-Item *.torrent
}

function Show-FlagNorway
{
    $sbRowCommon = {
        Write-Host (" " * 12) -BackgroundColor Red -NoNewline
        Write-Host (" " * 2) -BackgroundColor White -NoNewline
        Write-Host (" " * 4) -BackgroundColor Blue -NoNewline
        Write-Host (" " * 2) -BackgroundColor White -NoNewline
        Write-Host (" " * 24) -BackgroundColor Red
    }
    $sbRegionTopBottom = { 1..6 | ForEach-Object { $sbRowCommon.Invoke() } }
    $sbRowSemiMiddle = {
        Write-Host (" " * 14) -BackgroundColor White -NoNewline
        Write-Host (" " * 4) -BackgroundColor Blue -NoNewline
        Write-Host (" " * 26) -BackgroundColor White
    }
    $sbRowTrueMiddle = {
        Write-Host (" " * 44) -BackgroundColor Blue
    }
    $sbRegionMiddle = {
        $sbRowSemiMiddle.Invoke()
        $sbRowTrueMiddle.Invoke()
        $sbRowTrueMiddle.Invoke()
        $sbRowSemiMiddle.Invoke()
    }

    & $sbRegionTopBottom
    & $sbRegionMiddle
    & $sbRegionTopBottom
}

# Set aliases
New-Alias -name winscp -value Start-Adm-Hubot-WinSCP -description "Start WinSCP as hs\adm_nyyo"
New-Alias -name hubot -value Start-Adm-Hubot -description "Start putty with -load vir-app5207.ipa.ihelse.net as hs\adm_nyyo"
New-Alias -name GAU -value Get-ADUserWithMemberOf -description "Get-ADUser with the MemberOf property"
New-Alias -name FAD -value Find-ADGroup -description "Get-ADGroup"
New-Alias -name code -value "C:\Program Files\Microsoft VS Code\Code.exe"
$PSDefaultParameterValues = @{"*-SMA*:WebServiceEndPoint"="https://vir-infra134.ihelse.net";"*-SMA*:Port"="9090";"Get-Help:ShowWindow"=$true}
