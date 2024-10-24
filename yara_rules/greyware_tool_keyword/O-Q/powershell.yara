rule powershell
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: obfuscation techniques with powershell
        // Reference: N/A
        $string1 = /\s\-ep\sBypass\-nop\sfunction\s.{0,1000}\[System\.Security\.Cryptography\.Aes\]\:\:Create\(\).{0,1000}\.CreateDecryptor\(\).{0,1000}\.TransformFinalBlock.{0,1000}\[System\.Text\.Encoding\]\:\:Utf8\.GetString/ nocase ascii wide
        // Description: obfuscation techniques with powershell
        // Reference: N/A
        $string2 = /\s\-ep\sUnrestricted\s\-nop\sfunction\s.{0,1000}\[System\.Security\.Cryptography\.Aes\]\:\:Create\(\).{0,1000}\.CreateDecryptor\(\).{0,1000}\.TransformFinalBlock.{0,1000}\[System\.Text\.Encoding\]\:\:Utf8\.GetString/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string3 = /\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force/ nocase ascii wide
        // Description: suspicious powershell arguments order used by many exploitation tools
        // Reference: N/A
        $string4 = /\s\-NOP\s\-WIND\sHIDDeN\s\-eXeC\sBYPASS\s\-NONI\s/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string5 = /\[System\.Environment\]\:\:GetEnvironmentVariable\(\'username\'\)/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string6 = /\\powershell\.exe.{0,1000}\s\+\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string7 = /\\powershell\.exe.{0,1000}\s\+\=hidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string8 = /\\powershell\.exe.{0,1000}\s\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file.  It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string9 = /\\powershell\.exe.{0,1000}\s\=hidden/ nocase ascii wide
        // Description: adding a DNS over HTTPS server with powershell
        // Reference: https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientdohserveraddress?view=windowsserver2022-ps
        $string10 = /Add\-DnsClientDohServerAddress\s.{0,1000}\-ServerAddress\s/ nocase ascii wide
        // Description: add exclusions for defender
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string11 = /Add\-MpPreference\s\-ExclusionPath\s\@\(\$env\:UserProfile\,\s\$env\:ProgramData\)\s\-ExclusionExtension\s\'\.exe\'\s\-Force/ nocase ascii wide
        // Description: Exclude powershell from defender detections
        // Reference: N/A
        $string12 = /Add\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe/ nocase ascii wide
        // Description: allows all users to access all computers with a specified configuration
        // Reference: N/A
        $string13 = /Add\-PswaAuthorizationRule\s\-UsernName\s\\.{0,1000}\s\-ComputerName\s\\.{0,1000}\s\-ConfigurationName\s\\/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string14 = /Add\-PswaAuthorizationRule.{0,1000}\-ComputerName\s/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string15 = /Add\-PswaAuthorizationRule.{0,1000}\-UserName\s/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string16 = /Add\-PswaAuthorizationRule.{0,1000}\-UserName\s/ nocase ascii wide
        // Description: install openssh server (critical on DC - must not be installed)
        // Reference: N/A
        $string17 = /Add\-WindowsCapability\s\-Online\s\-Name\sOpenSSH\.Server/ nocase ascii wide
        // Description: Deletes contents of recycle bin
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string18 = /Clear\-RecycleBin\s\-Force\s\-ErrorAction\sSilentlyContinue/ nocase ascii wide
        // Description: Jenkins Abuse Without admin access
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string19 = /cmd\.exe\s\/c\sPowerShell\.exe\s\-Exec\sByPass\s\-Nol\s\-Enc\s/ nocase ascii wide
        // Description: Copy file to startup via Powershell
        // Reference: N/A
        $string20 = /copy\-item\s.{0,1000}\\roaming\\microsoft\\windows\\start\smenu\\programs\\startup/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string21 = /dism\s\s\/online\s\/enable\-feature\s\/featurename\:IIS\-WebServerRole\s\/all/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string22 = /dism\s\s\/online\s\/enable\-feature\s\/featurename\:WindowsPowerShellWebAccess\s\/all/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string23 = /dism\.exe.{0,1000}\/enable\-feature.{0,1000}WindowsPowerShellWebAccess\s/ nocase ascii wide
        // Description: enables WinRM
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string24 = /enable\-psremoting\s\-force/ nocase ascii wide
        // Description: Enabling PowerShell 2.0 Engine - downgrading to powershell version 2
        // Reference: N/A
        $string25 = /Enable\-WindowsOptionalFeature\s\-Online\s\-FeatureName\sMicrosoftWindowsPowerShellV2Root\s\-All/ nocase ascii wide
        // Description: Find machine where the user has admin privs
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string26 = /Find\-LocalAdminAccess\s\-Verbose/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string27 = /gci\senv\:USERNAME/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string28 = /gci\s\-h\sC\:\\pagefile\.sys/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string29 = /Get\-ADComputer\s\-Filter\s\{TrustedForDelegation\s\-eq\s\$True\}/ nocase ascii wide
        // Description: AD Module Search for a particular string in attributes (admin)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string30 = /Get\-ADGroup\s\-Filter\s.{0,1000}Name\s\-like\s.{0,1000}admin/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string31 = /Get\-ADObject\s\-Filter\s\{msDS\-AllowedToDelegateTo\s.{0,1000}\s\-Properties\smsDS\-AllowedToDelegateTo/ nocase ascii wide
        // Description: Enumerate shadow security principals mapped to a high priv group
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string32 = /Get\-ADObject\s\-SearchBase\s.{0,1000}CN\=Shadow\sPrincipal\sConfiguration.{0,1000}CN\=Services.{0,1000}\s\(Get\-ADRootDSE\)\.configurationNamingContext\)\s\|\sselect\s.{0,1000}msDS\-ShadowPrincipalSid/ nocase ascii wide
        // Description: AD module Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string33 = /Get\-ADUser\s\-Filter\s\{DoesNotRequirePreAuth\s\-eq\s\$True\}\s\-Properties\sDoesNotRequirePreAuth/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string34 = /Get\-ADUser\s\-Filter\s\{TrustedForDelegation\s\-eq\s\$True\}/ nocase ascii wide
        // Description: AppLocker Get AppLocker policy
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string35 = /Get\-AppLockerPolicy\s\-Effective\s/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string36 = /Get\-ChildItem\s\-Hidden\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string37 = /Get\-ChildItem\s\-Hidden\sC\:\\Users\\.{0,1000}\\AppData\\Roaming\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: set the DNS server configuration
        // Reference: N/A
        $string38 = /Get\-DhcpServerv4Scope\s\|\sSet\-DhcpServerv4OptionValue\s\-DnsServer\s/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string39 = /Get\-DomainComputer\s\-TrustedToAuth/ nocase ascii wide
        // Description: Powerview Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string40 = /Get\-DomainUser\s\-KerberosPreuthNotRequired\s\-Verbose/ nocase ascii wide
        // Description: AD Module GroupPolicy - List of GPO in the domain
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string41 = /Get\-GPO\s\-All/ nocase ascii wide
        // Description: PowerView get Locally logged users on a machine
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string42 = /Get\-LoggedonLocal\s\-ComputerName\s/ nocase ascii wide
        // Description: Gets the status of antimalware software on the computer.
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string43 = /Get\-MpComputerStatus/ nocase ascii wide
        // Description: get defender AV exclusions
        // Reference: N/A
        $string44 = /Get\-MpPreference\s\|\sSelect\-Object\s\-ExpandProperty\sExclusionPath/ nocase ascii wide
        // Description: Find groups in the current domain (PowerView)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string45 = /Get\-NetGroup\s\-FullData/ nocase ascii wide
        // Description: the command is used to discover the members of a specific domain group DNSAdmins which can provide an adversary with valuable information about the target environment. The knowledge of group members can be exploited by attackers to identify potential targets for privilege escalation or Lateral Movement within the network.
        // Reference: N/A
        $string46 = /Get\-NetGroupMember\s\-GroupName\s.{0,1000}DNSAdmins/ nocase ascii wide
        // Description: PowerView Find users with SPN
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string47 = /Get\-NetUser\s\-SPN/ nocase ascii wide
        // Description: delete shadow copies
        // Reference: https://rexorvc0.com/2024/06/19/Akira-The-Old-New-Style-Crime/
        $string48 = /Get\-WmiObject\sWin32_ShadowCopy\s\|\sRemove\-WmiObject/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string49 = /HostVersion\=2\.0.{0,1000}EngineVersion\=2\.0/ nocase ascii wide
        // Description: download from github from memory
        // Reference: N/A
        $string50 = /IEX\(New\-Object\sSystem\.Net\.WebClient\)\.DownloadString\(\"https\:\/\/raw\.githubusercontent\.com\// nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string51 = /Install\-PswaWebApplication\s\-UseTestCertificate/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string52 = /Install\-PswaWebApplication/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string53 = /Install\-WindowsFeature\s\-Name\sWeb\-Server\s\-IncludeManagementTools/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string54 = /Install\-WindowsFeature\sWindowsPowerShellWebAccess/ nocase ascii wide
        // Description: Find local admins on the domain machines
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string55 = /Invoke\-EnumerateLocalAdmin\s\-Verbose/ nocase ascii wide
        // Description: Check local admin access for the current user where the targets are found
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string56 = /Invoke\-UserHunter\s\-CheckAccess/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string57 = /Invoke\-WebRequest\sifconfig\.me\/ip.{0,1000}Content\.Trim\(\)/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string58 = /ls\senv\:USERNAME/ nocase ascii wide
        // Description: hiding a user from the login screen by modifying a specific registry key
        // Reference: N/A
        $string59 = /New\-ItemProperty\s\-Path\s\"HKLM\:\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\"\s\-Name\s.{0,1000}\s\-Value\s0\s\-PropertyType\sDword/ nocase ascii wide
        // Description: allowing SSH incoming connections (critical on DC)
        // Reference: N/A
        $string60 = /New\-NetFirewallRule\s.{0,1000}\s\-Enabled\sTrue\s\-Direction\sInbound\s\-Protocol\sTCP\s\-Action\sAllow\s\-LocalPort\s22/ nocase ascii wide
        // Description: Powershell reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string61 = /New\-Object\sSystem\.Net\.Sockets\.TCPClient\(.{0,1000}\$stream\s\=\s\$client\.GetStream\(\).{0,1000}\[byte\[\]\]\$bytes\s\=\s0\.\.65535/ nocase ascii wide
        // Description: Execution Policy Bypass evasion
        // Reference: N/A
        $string62 = /powershell\s\?encodedcommand\s\$env\:PSExecutionPolicyPreference\=\"bypass\"/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string63 = /powershell\s\-c\s.{0,1000}\\windows\\system32\\inetsrv\\appcmd\.exe\slist\sapppool\s\/\@t\:/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string64 = /powershell\sNew\-ItemProperty\s\-Path\s.{0,1000}HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force/ nocase ascii wide
        // Description: uninstalls Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string65 = /powershell\sUninstall\-WindowsFeature\s\-Name\sWindows\-Defender/ nocase ascii wide
        // Description: PowerShell Downgrade Attacks - forces PowerShell to run in version 2.0
        // Reference: N/A
        $string66 = /PowerShell\s\-Version\s2\s\-Command\s/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string67 = /powershell\s\-Version\s2/ nocase ascii wide
        // Description: Windows Defender tampering technique 
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string68 = /powershell.{0,1000}Uninstall\-WindowsFeature\s\-Name\sWindows\-Defender\-GUI/ nocase ascii wide
        // Description: Adversaries may attempt to execute powershell script from known accessible location
        // Reference: N/A
        $string69 = /Powershell\.exe\s\s\-windowstyle\shidden\s\-nop\s\-ExecutionPolicy\sBypass\s\s\-Commmand\s.{0,1000}C\:\\Users\\.{0,1000}\\AppData\\Roaming\\/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string70 = /powershell\.exe\scurl\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string71 = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string72 = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C.{0,1000}invoke_obfuscation/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string73 = /powershell\.exe\sInvoke\-WebRequest\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string74 = /powershell\.exe\siwr\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string75 = /powershell\.exe\s\-noni\s\-nop\s\-w\s1\s\-enc\s/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string76 = /powershell\.exe\s\-NoP\s\-NoL\s\-sta\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Enc\s/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string77 = /powershell\.exe\s\-nop\s\-w\shidden\s\-c\s\"IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'http\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: PowerShell Downgrade Attacks - forces PowerShell to run in version 2.0
        // Reference: N/A
        $string78 = /PowerShell\.exe\s\-Version\s2\s\-Command\s/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string79 = /powershell\.exe\s\-Version\s2/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string80 = /powershell\.exe\swget\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string81 = /powershell\.exe\"\s\-Version\s2/ nocase ascii wide
        // Description: attempts to evade defenses or remove traces of activity by deleting MRUList registry keys
        // Reference: N/A
        $string82 = /reg\sdelete\s.{0,1000}\s\/v\sMRUList\s\/f/ nocase ascii wide
        // Description: attempts to evade defenses or remove traces of activity by deleting MRUList registry keys
        // Reference: N/A
        $string83 = /Remove\-ItemProperty\s\-Path.{0,1000}\s\-Name\sMRUList\s/ nocase ascii wide
        // Description: list AV products with powershell
        // Reference: N/A
        $string84 = /root\/SecurityCenter2.{0,1000}\s\-ClassName\sAntiVirusProduct/ nocase ascii wide
        // Description: AMSI bypass obfuscation pattern
        // Reference: N/A
        $string85 = /S\`eT\-It\`em\s\(\s\'V\'\+\'aR\'\s\+\s\s\'IA\'\s\+\s\(\'blE\:1\'\+\'q2\'\)/ nocase ascii wide
        // Description: AD module Logon Script from remote IP
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string86 = /Set\-ADObject\s\-SamAccountName\s.{0,1000}\s\-PropertyName\sscriptpath\s\-PropertyValue\s.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Clearing the clipboard is a deliberate attempt to cover tracks and make the attack less detectable
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string87 = /Set\-Clipboard\s\-Value\s\'\s\'/ nocase ascii wide
        // Description: Clearing the clipboard is a deliberate attempt to cover tracks and make the attack less detectable
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string88 = /Set\-Clipboard\s\-Value\s\'\'/ nocase ascii wide
        // Description: Disable IPS
        // Reference: N/A
        $string89 = /Set\-MPPreference\s\-DisableIntrusionPreventionSystem\s\$true/ nocase ascii wide
        // Description: Disable scanning all downloaded files and attachments
        // Reference: N/A
        $string90 = /Set\-MpPreference\s\-DisableIOAVProtection\s\$true/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string91 = /Set\-MpPreference\s\-DisableRealtimeMonitoring\s\$true/ nocase ascii wide
        // Description: Disable AMSI (set to 0 to enable)
        // Reference: N/A
        $string92 = /Set\-MpPreference\s\-DisableScriptScanning\s1\s/ nocase ascii wide
        // Description: exclude exe file extensions from AV detections
        // Reference: https://github.com/Akabanwa-toma/hacke/blob/aaebb5cb188eb3a17bebfedfbde6b354e5522b92/installer.bat#L29C21-L29C63
        $string93 = /Set\-MpPreference\s\-ExclusionExtension\sexe/ nocase ascii wide
        // Description: openssh server is used (critical on DC - must not be installed)
        // Reference: N/A
        $string94 = /Set\-Service\s\-Name\ssshd\s\-StartupType\s\'Automatic\'/ nocase ascii wide
        // Description: openssh server is used (critical on DC - must not be installed)
        // Reference: N/A
        $string95 = /Start\-Service\ssshd/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string96 = /Stop\-Process\s\-Name\s\"Sophos\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string97 = /Stop\-Process\s\-Name\s\"SQL\sBackups\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string98 = /Stop\-Process\s\-Name\s\"SQLsafe\sBackup\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string99 = /Stop\-Process\s\-Name\s\"storagecraft\simagemanager.{0,1000}\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string100 = /Stop\-Process\s\-Name\s\"Symantec\sSystem\sRecovery\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string101 = /Stop\-Process\s\-Name\s\"Veeam\sBackup\sCatalog\sData\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string102 = /Stop\-Process\s\-Name\s\"Zoolz\s2\sService\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string103 = /Stop\-Process\s\-Name\sacronisagent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string104 = /Stop\-Process\s\-Name\sAcronisAgent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string105 = /Stop\-Process\s\-Name\sacrsch2svc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string106 = /Stop\-Process\s\-Name\sAcrSch2Svc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string107 = /Stop\-Process\s\-Name\sagntsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string108 = /Stop\-Process\s\-Name\sAntivirus/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string109 = /Stop\-Process\s\-Name\sARSM\s\/y/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string110 = /Stop\-Process\s\-Name\sarsm/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string111 = /Stop\-Process\s\-Name\sAVP/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string112 = /Stop\-Process\s\-Name\sbackp/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string113 = /Stop\-Process\s\-Name\sbackup/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string114 = /Stop\-Process\s\-Name\sBackupExec/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string115 = /Stop\-Process\s\-Name\sBackupExecAgent/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string116 = /Stop\-Process\s\-Name\sbedbg\s\/y/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string117 = /Stop\-Process\s\-Name\scbservi/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string118 = /Stop\-Process\s\-Name\scbvscserv/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string119 = /Stop\-Process\s\-Name\sDCAgent/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string120 = /Stop\-Process\s\-Name\sEhttpSrv/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string121 = /Stop\-Process\s\-Name\sekrn/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string122 = /Stop\-Process\s\-Name\sEPSecurityService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string123 = /Stop\-Process\s\-Name\sEPUpdateService.{0,1000}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string124 = /Stop\-Process\s\-Name\sEsgShKernel/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string125 = /Stop\-Process\s\-Name\sESHASRV/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string126 = /Stop\-Process\s\-Name\sFA_Scheduler/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string127 = /Stop\-Process\s\-Name\sIMAP4Svc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string128 = /Stop\-Process\s\-Name\sKAVFS/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string129 = /Stop\-Process\s\-Name\sKAVFSGT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string130 = /Stop\-Process\s\-Name\skavfsslp/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string131 = /Stop\-Process\s\-Name\sklnagent/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string132 = /Stop\-Process\s\-Name\smacmnsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string133 = /Stop\-Process\s\-Name\smasvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string134 = /Stop\-Process\s\-Name\sMBAMService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string135 = /Stop\-Process\s\-Name\sMBEndpointAgent.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string136 = /Stop\-Process\s\-Name\sMcAfeeEngineService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string137 = /Stop\-Process\s\-Name\sMcAfeeFramework/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string138 = /Stop\-Process\s\-Name\sMcAfeeFrameworkMcAfeeFramework/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string139 = /Stop\-Process\s\-Name\sMcShield/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string140 = /Stop\-Process\s\-Name\smfefire/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string141 = /Stop\-Process\s\-Name\smfemms/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string142 = /Stop\-Process\s\-Name\smfevtp/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string143 = /Stop\-Process\s\-Name\smozyprobackup/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string144 = /Stop\-Process\s\-Name\sMsDtsServer/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string145 = /Stop\-Process\s\-Name\sMsDtsServer100/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string146 = /Stop\-Process\s\-Name\sMsDtsServer110/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string147 = /Stop\-Process\s\-Name\smsftesql\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string148 = /Stop\-Process\s\-Name\sMSOLAP\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string149 = /Stop\-Process\s\-Name\sMSOLAP\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string150 = /Stop\-Process\s\-Name\sMSOLAP\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string151 = /Stop\-Process\s\-Name\sMSOLAP\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string152 = /Stop\-Process\s\-Name\sMSSQL\$BKUPEXEC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string153 = /Stop\-Process\s\-Name\sMSSQL\$ECWDB2/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string154 = /Stop\-Process\s\-Name\sMSSQL\$PRACTICEMGT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string155 = /Stop\-Process\s\-Name\sMSSQL\$PRACTTICEBGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string156 = /Stop\-Process\s\-Name\sMSSQL\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string157 = /Stop\-Process\s\-Name\sMSSQL\$PROFXENGAGEMENT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string158 = /Stop\-Process\s\-Name\sMSSQL\$SBSMONITORING/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string159 = /Stop\-Process\s\-Name\sMSSQL\$SHAREPOINT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string160 = /Stop\-Process\s\-Name\sMSSQL\$SOPHOS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string161 = /Stop\-Process\s\-Name\sMSSQL\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string162 = /Stop\-Process\s\-Name\sMSSQL\$SQLEXPRESS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string163 = /Stop\-Process\s\-Name\sMSSQL\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string164 = /Stop\-Process\s\-Name\sMSSQL\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string165 = /Stop\-Process\s\-Name\sMSSQL\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string166 = /Stop\-Process\s\-Name\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string167 = /Stop\-Process\s\-Name\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string168 = /Stop\-Process\s\-Name\ssacsvr/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string169 = /Stop\-Process\s\-Name\sSAVAdminService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string170 = /Stop\-Process\s\-Name\sSAVService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string171 = /Stop\-Process\s\-Name\sshadowprotectsvc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string172 = /Stop\-Process\s\-Name\sShMonitor/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string173 = /Stop\-Process\s\-Name\sSmcinst/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string174 = /Stop\-Process\s\-Name\sSmcService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string175 = /Stop\-Process\s\-Name\ssms_site_sql_backup/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string176 = /Stop\-Process\s\-Name\sSntpService.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string177 = /Stop\-Process\s\-Name\ssophossps/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string178 = /Stop\-Process\s\-Name\sspxservice/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string179 = /Stop\-Process\s\-Name\ssqbcoreservice/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string180 = /Stop\-Process\s\-Name\sSQLAgent\$SOPH/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string181 = /Stop\-Process\s\-Name\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string182 = /Stop\-Process\s\-Name\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string183 = /Stop\-Process\s\-Name\sstc_endpt_svc/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string184 = /Stop\-Process\s\-Name\sstop\sSepMasterService/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string185 = /Stop\-Process\s\-Name\ssvcGenericHost/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string186 = /Stop\-Process\s\-Name\sswi_filter/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string187 = /Stop\-Process\s\-Name\sswi_service/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string188 = /Stop\-Process\s\-Name\sswi_update/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string189 = /Stop\-Process\s\-Name\sswi_update_64/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string190 = /Stop\-Process\s\-Name\sTmCCSF/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string191 = /Stop\-Process\s\-Name\stmlisten/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string192 = /Stop\-Process\s\-Name\sTrueKey/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string193 = /Stop\-Process\s\-Name\sTrueKeyScheduler.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string194 = /Stop\-Process\s\-Name\sTrueKeyServiceHel/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string195 = /Stop\-Process\s\-Name\svapiendpoint.{0,1000}\s\s\s\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string196 = /Stop\-Process\s\-Name\sVeeamBackupSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string197 = /Stop\-Process\s\-Name\sVeeamBrokerSvc\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string198 = /Stop\-Process\s\-Name\sVeeamCatalogSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string199 = /Stop\-Process\s\-Name\sVeeamCloudSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string200 = /Stop\-Process\s\-Name\sVeeamDeploymentService/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string201 = /Stop\-Process\s\-Name\sVeeamDeploySvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string202 = /Stop\-Process\s\-Name\sVeeamDeploySvc.{0,1000}\s\s\s\s/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string203 = /Stop\-Process\s\-Name\sVeeamEnterpriseManagerSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string204 = /Stop\-Process\s\-Name\sVeeamHvIntegrationSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string205 = /Stop\-Process\s\-Name\sVeeamMountSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string206 = /Stop\-Process\s\-Name\sVeeamNFSSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string207 = /Stop\-Process\s\-Name\sVeeamRESTSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string208 = /Stop\-Process\s\-Name\sVeeamTransportSvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string209 = /Stop\-Process\s\-Name\svsnapvss/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string210 = /Stop\-Process\s\-Name\svssvc/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string211 = /Stop\-Process\s\-Name\swbengine/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string212 = /Stop\-Process\s\-Name\swbengine/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string213 = /Stop\-Process\s\-Name\sWRSVC/ nocase ascii wide

    condition:
        any of them
}
