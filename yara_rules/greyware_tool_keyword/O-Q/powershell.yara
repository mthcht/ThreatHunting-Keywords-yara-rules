rule powershell
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string1 = /\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string2 = /\[System\.Environment\]\:\:GetEnvironmentVariable\(\'username\'\)/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string3 = /\\powershell\.exe.{0,1000}\s\+\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string4 = /\\powershell\.exe.{0,1000}\s\+\=hidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string5 = /\\powershell\.exe.{0,1000}\s\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file.  It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string6 = /\\powershell\.exe.{0,1000}\s\=hidden/ nocase ascii wide
        // Description: adding a DNS over HTTPS server with powershell
        // Reference: https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientdohserveraddress?view=windowsserver2022-ps
        $string7 = /Add\-DnsClientDohServerAddress\s.{0,1000}\-ServerAddress\s/ nocase ascii wide
        // Description: add exclusions for defender
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string8 = /Add\-MpPreference\s\-ExclusionPath\s\@\(\$env\:UserProfile\,\s\$env\:ProgramData\)\s\-ExclusionExtension\s\'\.exe\'\s\-Force/ nocase ascii wide
        // Description: Exclude powershell from defender detections
        // Reference: N/A
        $string9 = /Add\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe/ nocase ascii wide
        // Description: allows all users to access all computers with a specified configuration
        // Reference: N/A
        $string10 = /Add\-PswaAuthorizationRule\s\-UsernName\s\\.{0,1000}\s\-ComputerName\s\\.{0,1000}\s\-ConfigurationName\s\\/ nocase ascii wide
        // Description: Deletes contents of recycle bin
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string11 = /Clear\-RecycleBin\s\-Force\s\-ErrorAction\sSilentlyContinue/ nocase ascii wide
        // Description: enables WinRM
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string12 = /enable\-psremoting\s\-force/ nocase ascii wide
        // Description: Find machine where the user has admin privs
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string13 = /Find\-LocalAdminAccess\s\-Verbose/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string14 = /gci\senv\:USERNAME/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string15 = /gci\s\-h\sC\:\\pagefile\.sys/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string16 = /Get\-ADComputer\s\-Filter\s\{TrustedForDelegation\s\-eq\s\$True\}/ nocase ascii wide
        // Description: AD Module Search for a particular string in attributes (admin)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string17 = /Get\-ADGroup\s\-Filter\s.{0,1000}Name\s\-like\s.{0,1000}admin/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string18 = /Get\-ADObject\s\-Filter\s\{msDS\-AllowedToDelegateTo\s.{0,1000}\s\-Properties\smsDS\-AllowedToDelegateTo/ nocase ascii wide
        // Description: Enumerate shadow security principals mapped to a high priv group
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string19 = /Get\-ADObject\s\-SearchBase\s.{0,1000}CN\=Shadow\sPrincipal\sConfiguration.{0,1000}CN\=Services.{0,1000}\s\(Get\-ADRootDSE\)\.configurationNamingContext\)\s\|\sselect\s.{0,1000}msDS\-ShadowPrincipalSid/ nocase ascii wide
        // Description: AD module Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string20 = /Get\-ADUser\s\-Filter\s\{DoesNotRequirePreAuth\s\-eq\s\$True\}\s\-Properties\sDoesNotRequirePreAuth/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string21 = /Get\-ADUser\s\-Filter\s\{TrustedForDelegation\s\-eq\s\$True\}/ nocase ascii wide
        // Description: AppLocker Get AppLocker policy
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string22 = /Get\-AppLockerPolicy\s\-Effective\s/ nocase ascii wide
        // Description: set the DNS server configuration
        // Reference: N/A
        $string23 = /Get\-DhcpServerv4Scope\s\|\sSet\-DhcpServerv4OptionValue\s\-DnsServer\s/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string24 = /Get\-DomainComputer\s\-TrustedToAuth/ nocase ascii wide
        // Description: Powerview Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string25 = /Get\-DomainUser\s\-KerberosPreuthNotRequired\s\-Verbose/ nocase ascii wide
        // Description: AD Module GroupPolicy - List of GPO in the domain
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string26 = /Get\-GPO\s\-All/ nocase ascii wide
        // Description: PowerView get Locally logged users on a machine
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string27 = /Get\-LoggedonLocal\s\-ComputerName\s/ nocase ascii wide
        // Description: Gets the status of antimalware software on the computer.
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string28 = /Get\-MpComputerStatus/ nocase ascii wide
        // Description: get defender AV exclusions
        // Reference: N/A
        $string29 = /Get\-MpPreference\s\|\sSelect\-Object\s\-ExpandProperty\sExclusionPath/ nocase ascii wide
        // Description: Find groups in the current domain (PowerView)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string30 = /Get\-NetGroup\s\-FullData/ nocase ascii wide
        // Description: the command is used to discover the members of a specific domain group DNSAdmins which can provide an adversary with valuable information about the target environment. The knowledge of group members can be exploited by attackers to identify potential targets for privilege escalation or Lateral Movement within the network.
        // Reference: N/A
        $string31 = /Get\-NetGroupMember\s\-GroupName\s.{0,1000}DNSAdmins/ nocase ascii wide
        // Description: PowerView Find users with SPN
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string32 = /Get\-NetUser\s\-SPN/ nocase ascii wide
        // Description: delete shadow copies
        // Reference: https://rexorvc0.com/2024/06/19/Akira-The-Old-New-Style-Crime/
        $string33 = /Get\-WmiObject\sWin32_ShadowCopy\s\|\sRemove\-WmiObject/ nocase ascii wide
        // Description: Find local admins on the domain machines
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string34 = /Invoke\-EnumerateLocalAdmin\s\-Verbose/ nocase ascii wide
        // Description: Check local admin access for the current user where the targets are found
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string35 = /Invoke\-UserHunter\s\-CheckAccess/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string36 = /Invoke\-WebRequest\sifconfig\.me\/ip.{0,1000}Content\.Trim\(\)/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string37 = /ls\senv\:USERNAME/ nocase ascii wide
        // Description: hiding a user from the login screen by modifying a specific registry key
        // Reference: N/A
        $string38 = /New\-ItemProperty\s\-Path\s\"HKLM\:\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\"\s\-Name\s.{0,1000}\s\-Value\s0\s\-PropertyType\sDword/ nocase ascii wide
        // Description: Powershell reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string39 = /New\-Object\sSystem\.Net\.Sockets\.TCPClient\(.{0,1000}\$stream\s\=\s\$client\.GetStream\(\).{0,1000}\[byte\[\]\]\$bytes\s\=\s0\.\.65535/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string40 = /powershell\s\-c\s.{0,1000}\\windows\\system32\\inetsrv\\appcmd\.exe\slist\sapppool\s\/\@t\:/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string41 = /powershell\sNew\-ItemProperty\s\-Path\s.{0,1000}HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force/ nocase ascii wide
        // Description: Windows Defender tampering technique 
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string42 = /powershell.{0,1000}Uninstall\-WindowsFeature\s\-Name\sWindows\-Defender\-GUI/ nocase ascii wide
        // Description: Adversaries may attempt to execute powershell script from known accessible location
        // Reference: N/A
        $string43 = /Powershell\.exe\s\s\-windowstyle\shidden\s\-nop\s\-ExecutionPolicy\sBypass\s\s\-Commmand\s.{0,1000}C\:\\Users\\.{0,1000}\\AppData\\Roaming\\/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string44 = /powershell\.exe\scurl\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string45 = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string46 = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C.{0,1000}invoke_obfuscation/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string47 = /powershell\.exe\sInvoke\-WebRequest\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string48 = /powershell\.exe\siwr\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string49 = /powershell\.exe\s\-noni\s\-nop\s\-w\s1\s\-enc\s/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string50 = /powershell\.exe\s\-NoP\s\-NoL\s\-sta\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Enc\s/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string51 = /powershell\.exe\s\-nop\s\-w\shidden\s\-c\s\"IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'http\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string52 = /powershell\.exe\swget\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: list AV products with powershell
        // Reference: N/A
        $string53 = /root\/SecurityCenter2.{0,1000}\s\-ClassName\sAntiVirusProduct/ nocase ascii wide
        // Description: Clearing the clipboard is a deliberate attempt to cover tracks and make the attack less detectable
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string54 = /Set\-Clipboard\s\-Value\s\'\s\'/ nocase ascii wide
        // Description: Clearing the clipboard is a deliberate attempt to cover tracks and make the attack less detectable
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string55 = /Set\-Clipboard\s\-Value\s\'\'/ nocase ascii wide
        // Description: Disable scanning all downloaded files and attachments
        // Reference: N/A
        $string56 = /Set\-MpPreference\s\-DisableIOAVProtection\s\$true/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string57 = /Set\-MpPreference\s\-DisableRealtimeMonitoring\s\$true/ nocase ascii wide
        // Description: Disable AMSI (set to 0 to enable)
        // Reference: N/A
        $string58 = /Set\-MpPreference\s\-DisableScriptScanning\s1\s/ nocase ascii wide
        // Description: exclude exe file extensions from AV detections
        // Reference: https://github.com/Akabanwa-toma/hacke/blob/aaebb5cb188eb3a17bebfedfbde6b354e5522b92/installer.bat#L29C21-L29C63
        $string59 = /Set\-MpPreference\s\-ExclusionExtension\sexe/ nocase ascii wide
        // Description: Jenkins Abuse Without admin access
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string60 = /cmd\.exe\s\/c\sPowerShell\.exe\s\-Exec\sByPass\s\-Nol\s\-Enc\s/ nocase ascii wide
        // Description: AD module Logon Script from remote IP
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string61 = /Set\-ADObject\s\-SamAccountName\s.{0,1000}\s\-PropertyName\sscriptpath\s\-PropertyValue\s.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
