rule powershell
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Suspicious PowerShell execution behavior often observed in FakeCaptcha phishing attempts
        // Reference: https://x.com/malware_traffic/status/1884476331821326816/photo/2
        $string1 = /\s\/c\sstart\s\/min\spowershell\s\-noprofile\s\-w\sH\s\-c\s.{0,1000}irw/ nocase ascii wide
        // Description: obfuscation techniques with powershell
        // Reference: N/A
        $string2 = /\s\-ep\sBypass\s\-nop\sfunction\s.{0,1000}\[System\.Security\.Cryptography\.Aes\]\:\:Create\(\).{0,1000}\.CreateDecryptor\(\).{0,1000}\.TransformFinalBlock.{0,1000}\[System\.Text\.Encoding\]\:\:Utf8\.GetString/ nocase ascii wide
        // Description: obfuscation techniques with powershell
        // Reference: N/A
        $string3 = /\s\-ep\sUnrestricted\s\-nop\sfunction\s.{0,1000}\[System\.Security\.Cryptography\.Aes\]\:\:Create\(\).{0,1000}\.CreateDecryptor\(\).{0,1000}\.TransformFinalBlock.{0,1000}\[System\.Text\.Encoding\]\:\:Utf8\.GetString/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string4 = " -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force" nocase ascii wide
        // Description: powershell command pattern used by sliver - an open source cross-platform adversary emulation/red team framework
        // Reference: https://github.com/BishopFox/sliver
        $string5 = /\s\-NoExit\s\-Command\s\[Console\]\:\:OutputEncoding\=\[Text\.UTF8Encoding\]\:\:UTF8/ nocase ascii wide
        // Description: reverse shell powershell
        // Reference: https://github.com/mthbernardes/rsg
        $string6 = /\s\-NoP\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Command\sNew\-Object\sSystem\.Net\.Sockets\.TCPClient/ nocase ascii wide
        // Description: suspicious powershell arguments order used by many exploitation tools
        // Reference: N/A
        $string7 = " -NOP -WIND HIDDeN -eXeC BYPASS -NONI " nocase ascii wide
        // Description: A PowerShell process downloaded and launched a remote file
        // Reference: N/A
        $string8 = /\s\-W\sHidden\s\-command\s.{0,1000}https\:\/\/.{0,1000}Invoke\-WebRequest.{0,1000}\;\siex\s\$/ nocase ascii wide
        // Description: A PowerShell process downloaded and launched a remote file
        // Reference: N/A
        $string9 = /\s\-W\sHidden\s\-command\s.{0,1000}Invoke\-WebRequest.{0,1000}https\:\/\/.{0,1000}\;\siex\s\$/ nocase ascii wide
        // Description: suspicious powershell command often used in recaptcha phishing campaign (run dialog)
        // Reference: N/A
        $string10 = /\s\-w\shidden\s\-ep\sbypass\s\-nop\s\-Command\s\\"iex\s\(\(New\-Object\sSystem\.Net\.WebClient\)\.DownloadString\(/ nocase ascii wide
        // Description: suspicious behavior powershell script
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string11 = /\\"\[IO\.File\]\:\:WriteAllBytes\(\$.{0,1000}\,\[Convert\]\:\:FromBase64String\(\\"/ nocase ascii wide
        // Description: Powershell enumerate domains and forests
        // Reference: https://medium.com/@simone.kraus/black-basta-playbook-chat-leak-d5036936166d
        $string12 = /\(\[System\.DirectoryServices\.ActiveDirectory\.Domain\]\:\:GetCurrentDomain\(\)\)\.GetAllTrustRelationships\(\)/ nocase ascii wide
        // Description: lolbin execution with COM object
        // Reference: https://github.com/xyddnljydd/ComClsIDInterefaceEnum
        $string13 = /\:\:CreateInstance\(\[type\]\:\:GetTypeFromCLSID\(\\"13709620\-C279\-11CE\-A49E\-444553540000/ nocase ascii wide
        // Description: lolbin execution with COM object
        // Reference: https://github.com/xyddnljydd/ComClsIDInterefaceEnum
        $string14 = /\:\:CreateInstance\(\[type\]\:\:GetTypeFromCLSID\(\\"33ABD590\-0400\-4FEF\-AF98\-5F5A8A99CFC3/ nocase ascii wide
        // Description: lolbin execution with COM object
        // Reference: https://github.com/xyddnljydd/ComClsIDInterefaceEnum
        $string15 = /\:\:CreateInstance\(\[type\]\:\:GetTypeFromCLSID\(\\"F935DC22\-1CF0\-11D0\-ADB9\-00C04FD58A0B\\"/ nocase ascii wide
        // Description: suspicious behavior powershell script
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string16 = /\[IO\.Path\]\:\:Combine\(\$env\:TEMP\,\\"x\.exe\\"\)/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string17 = /\[System\.Environment\]\:\:GetEnvironmentVariable\(\'username\'\)/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string18 = /\\powershell\.exe.{0,1000}\s\+\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string19 = /\\powershell\.exe.{0,1000}\s\+\=hidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string20 = /\\powershell\.exe.{0,1000}\s\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file.  It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string21 = /\\powershell\.exe.{0,1000}\s\=hidden/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string22 = /\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels.{0,1000}\s\-Name\s\\"DisableDevTunnelsInVisualStudio\\"\s\-Value\s0\s\-Type\sDword/ nocase ascii wide
        // Description: Once AccessVBOM is enabled - an attacker can use VBA to embed or execute malicious code
        // Reference: https://blog.sekoia.io/double-tap-campaign-russia-nexus-apt-possibly-related-to-apt28-conducts-cyber-espionage-on-central-asia-and-kazakhstan-diplomatic-relations/
        $string23 = /\\Word\\Security\\"\s\-Name\s\\"AccessVBOM\\"\s\-Value\s1\s\-Type\sDword/ nocase ascii wide
        // Description: ESX treats all members of an Active Directory group named "ESX Admins" as administrators by default. Attackers have exploited this misconfiguration to escalate privileges and gain administrative access.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string24 = "Add-ADGroupMember -Identity  \"ESX Admins\"" nocase ascii wide
        // Description: adding a DNS over HTTPS server with powershell
        // Reference: https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientdohserveraddress?view=windowsserver2022-ps
        $string25 = /Add\-DnsClientDohServerAddress\s.{0,1000}\-ServerAddress\s/ nocase ascii wide
        // Description: add exclusions for defender
        // Reference: https://www.virustotal.com/gui/file/00820a1f0972678cfe7885bc989ab3e5602b0febc96baf9bf3741d56aa374f03/behavior
        $string26 = /Add\-MpPreference\s\-ExclusionPath\s\@\(\$env\:UserProfile\,\s\$env\:ProgramData\)\s\-ExclusionExtension\s\'\.exe\'\s\-Force/ nocase ascii wide
        // Description: AV exclusions made by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string27 = /Add\-MpPreference\s\-ExclusionPath\sC\:\\Video\,\sC\:\\install/ nocase ascii wide
        // Description: Exclude powershell from defender detections
        // Reference: N/A
        $string28 = /Add\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe/ nocase ascii wide
        // Description: allows all users to access all computers with a specified configuration
        // Reference: N/A
        $string29 = /Add\-PswaAuthorizationRule\s\-UsernName\s\\.{0,1000}\s\-ComputerName\s\\.{0,1000}\s\-ConfigurationName\s\\/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string30 = /Add\-PswaAuthorizationRule.{0,1000}\-ComputerName\s/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string31 = /Add\-PswaAuthorizationRule.{0,1000}\-UserName\s/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string32 = /Add\-PswaAuthorizationRule.{0,1000}\-UserName\s/ nocase ascii wide
        // Description: install openssh server (critical on DC - must not be installed)
        // Reference: N/A
        $string33 = /Add\-WindowsCapability\s\-Online\s\-Name\sOpenSSH\.Server/ nocase ascii wide
        // Description: enabling hyperV - virtualization could be abused by attacker to maintain persistence in a virtual machine
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string34 = "Add-WindowsFeature Hyper-V -IncludeManagementTools" nocase ascii wide
        // Description: backs up all Group Policy Objects (GPOs) to a specified path
        // Reference: N/A
        $string35 = "Backup-GPO -All -Path " nocase ascii wide
        // Description: clearing security logs with powershell
        // Reference: N/A
        $string36 = "Clear-EventLog -LogName Security" nocase ascii wide
        // Description: Deletes contents of recycle bin
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string37 = "Clear-RecycleBin -Force -ErrorAction SilentlyContinue" nocase ascii wide
        // Description: Jenkins Abuse Without admin access
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string38 = /cmd\.exe\s\/c\sPowerShell\.exe\s\-Exec\sByPass\s\-Nol\s\-Enc\s/ nocase ascii wide
        // Description: establishes a TCP connection to a remote server - likely for C2 or payload delivery?.
        // Reference: https://medium.com/@simone.kraus/black-basta-playbook-chat-leak-d5036936166d
        $string39 = "Connect-SocksServer -Server " nocase ascii wide
        // Description: Copy file to startup via Powershell
        // Reference: N/A
        $string40 = /copy\-item\s.{0,1000}\\roaming\\microsoft\\windows\\start\smenu\\programs\\startup/ nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string41 = "dism  /online /enable-feature /featurename:IIS-WebServerRole /all" nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string42 = "dism  /online /enable-feature /featurename:WindowsPowerShellWebAccess /all" nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string43 = /dism\.exe.{0,1000}\/enable\-feature.{0,1000}WindowsPowerShellWebAccess\s/ nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string44 = "DisplayName -match \"Sophos Anti-Virus\"" nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string45 = "DisplayName -match \"Sophos AutoUpdate\"" nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string46 = "DisplayName -match \"Sophos Client Firewall\"" nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string47 = "DisplayName -match \"Sophos Endpoint Defense\"" nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string48 = "DisplayName -match \"Sophos Network Threat Protection\"" nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string49 = "DisplayName -match \"Sophos Remote Management System\"" nocase ascii wide
        // Description: Uninstall Sophos - searching for the name
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string50 = "DisplayName -match \"Sophos System Protection\"" nocase ascii wide
        // Description: enables WinRM
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt/blob/alperen_ugurlu_hack/AD_Enumeration_Hunt.ps1
        $string51 = "enable-psremoting -force" nocase ascii wide
        // Description: enabling hyperV - virtualization could be abused by attacker to maintain persistence in a virtual machine
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string52 = "Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All" nocase ascii wide
        // Description: Enabling PowerShell 2.0 Engine - downgrading to powershell version 2
        // Reference: N/A
        $string53 = "Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -All" nocase ascii wide
        // Description: enabling hyperV - virtualization could be abused by attacker to maintain persistence in a virtual machine
        // Reference: https://embracethered.com/blog/posts/2020/shadowbunny-virtual-machine-red-teaming-technique/
        $string54 = /Enable\-WindowsOptionalFeature\s\-Online\:\$true\s\-FeatureName\sMicrosoft\-Hyper\-V\s\-All\:\$true/ nocase ascii wide
        // Description: Find machine where the user has admin privs
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string55 = "Find-LocalAdminAccess -Verbose" nocase ascii wide
        // Description: port scanner with powershell command test-NetConnection
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string56 = /foreach\s\(\$.{0,1000}\s\{Test\-NetConnection\s\-Port\s/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string57 = "gci env:USERNAME" nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string58 = /gci\s\-h\sC\:\\pagefile\.sys/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string59 = /Get\-ADComputer\s\-Filter\s\{TrustedForDelegation\s\-eq\s\$True\}/ nocase ascii wide
        // Description: AD Module Search for a particular string in attributes (admin)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string60 = /Get\-ADGroup\s\-Filter\s.{0,1000}Name\s\-like\s.{0,1000}admin/ nocase ascii wide
        // Description: Powershell enumerate domains and forests
        // Reference: N/A
        $string61 = "Get-ADGroupMember Administrators -Recursive" nocase ascii wide
        // Description: List the members of the "Domain Admins" group within Active Directory
        // Reference: N/A
        $string62 = "Get-ADGroupMember -Identity \"Domain Admins\"" nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string63 = /Get\-ADObject\s\-Filter\s\{msDS\-AllowedToDelegateTo\s.{0,1000}\s\-Properties\smsDS\-AllowedToDelegateTo/ nocase ascii wide
        // Description: Enumerate shadow security principals mapped to a high priv group
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string64 = /Get\-ADObject\s\-SearchBase\s.{0,1000}CN\=Shadow\sPrincipal\sConfiguration.{0,1000}CN\=Services.{0,1000}\s\(Get\-ADRootDSE\)\.configurationNamingContext\)\s\|\sselect\s.{0,1000}msDS\-ShadowPrincipalSid/ nocase ascii wide
        // Description: AD module Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string65 = /Get\-ADUser\s\-Filter\s\{DoesNotRequirePreAuth\s\-eq\s\$True\}\s\-Properties\sDoesNotRequirePreAuth/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string66 = /Get\-ADUser\s\-Filter\s\{TrustedForDelegation\s\-eq\s\$True\}/ nocase ascii wide
        // Description: AppLocker Get AppLocker policy
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string67 = "Get-AppLockerPolicy -Effective " nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string68 = /Get\-ChildItem\s\-Hidden\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: Find Potential Credential in Files - This directory often contains encrypted credentials or other sensitive files related to user accounts
        // Reference: N/A
        $string69 = /Get\-ChildItem\s\-Hidden\sC\:\\Users\\.{0,1000}\\AppData\\Roaming\\Microsoft\\Credentials\\/ nocase ascii wide
        // Description: set the DNS server configuration
        // Reference: N/A
        $string70 = /Get\-DhcpServerv4Scope\s\|\sSet\-DhcpServerv4OptionValue\s\-DnsServer\s/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string71 = "Get-DomainComputer -TrustedToAuth" nocase ascii wide
        // Description: Powerview Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string72 = "Get-DomainUser -KerberosPreuthNotRequired -Verbose" nocase ascii wide
        // Description: AD Module GroupPolicy - List of GPO in the domain
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string73 = "Get-GPO -All" nocase ascii wide
        // Description: PowerView get Locally logged users on a machine
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string74 = "Get-LoggedonLocal -ComputerName " nocase ascii wide
        // Description: Gets the status of antimalware software on the computer.
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string75 = "Get-MpComputerStatus" nocase ascii wide
        // Description: get defender AV exclusions
        // Reference: N/A
        $string76 = /Get\-MpPreference\s\|\sSelect\-Object\s\-ExpandProperty\sExclusionPath/ nocase ascii wide
        // Description: Find groups in the current domain (PowerView)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string77 = "Get-NetGroup -FullData" nocase ascii wide
        // Description: the command is used to discover the members of a specific domain group DNSAdmins which can provide an adversary with valuable information about the target environment. The knowledge of group members can be exploited by attackers to identify potential targets for privilege escalation or Lateral Movement within the network.
        // Reference: N/A
        $string78 = /Get\-NetGroupMember\s\-GroupName\s.{0,1000}DNSAdmins/ nocase ascii wide
        // Description: PowerView Find users with SPN
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string79 = "Get-NetUser -SPN" nocase ascii wide
        // Description: delete shadow copies
        // Reference: https://rexorvc0.com/2024/06/19/Akira-The-Old-New-Style-Crime/
        $string80 = /Get\-WmiObject\sWin32_ShadowCopy\s\|\sRemove\-WmiObject/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string81 = /HostVersion\=2\.0.{0,1000}EngineVersion\=2\.0/ nocase ascii wide
        // Description: suspicious base64 execution often observed by stealers - could also be used legitimely by some script
        // Reference: N/A
        $string82 = /IEX\s\(\[System\.Text\.Encoding\]\:\:UTF8\.GetString\(\[System\.Convert\]\:\:FromBase64String\(/ nocase ascii wide
        // Description: download from github from memory
        // Reference: N/A
        $string83 = /IEX\(New\-Object\sSystem\.Net\.WebClient\)\.DownloadString\(\\"https\:\/\/raw\.githubusercontent\.com\// nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string84 = "Install-PswaWebApplication -UseTestCertificate" nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string85 = "Install-PswaWebApplication" nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string86 = "Install-WindowsFeature -Name Web-Server -IncludeManagementTools" nocase ascii wide
        // Description: enable the PowerShell Web Access featur which could be used for remote access and potential
        // Reference: https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
        $string87 = "Install-WindowsFeature WindowsPowerShellWebAccess" nocase ascii wide
        // Description: Find local admins on the domain machines
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string88 = "Invoke-EnumerateLocalAdmin -Verbose" nocase ascii wide
        // Description: suspicious base64 execution often observed by stealers - could also be used legitimely by some script
        // Reference: N/A
        $string89 = /invoke\-expression\(\[System\.Text\.Encoding\]\:\:UTF8\.GetString\(\[System\.Convert\]\:\:FromBase64String\(/ nocase ascii wide
        // Description: Check local admin access for the current user where the targets are found
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string90 = "Invoke-UserHunter -CheckAccess" nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string91 = /Invoke\-WebRequest\sifconfig\.me\/ip.{0,1000}Content\.Trim\(\)/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string92 = "ls env:USERNAME" nocase ascii wide
        // Description: ESX treats all members of an Active Directory group named "ESX Admins" as administrators by default. Attackers have exploited this misconfiguration to escalate privileges and gain administrative access.
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string93 = "New-ADGroup -Name \"ESX Admins\"" nocase ascii wide
        // Description: hiding a user from the login screen by modifying a specific registry key
        // Reference: N/A
        $string94 = /New\-ItemProperty\s\-Path\s\\"HKLM\:\\Software\\Microsoft\\Windows\sNT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist\\"\s\-Name\s.{0,1000}\s\-Value\s0\s\-PropertyType\sDword/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string95 = /New\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels\\"\s\-Name\s\\"DisableDevTunnelsInVisualStudio\\"\s\-PropertyType\sDWORD\s\-Value\s0/ nocase ascii wide
        // Description: completely disable Windows Defender on your computer by adding a registry key
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string96 = /New\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\\"\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force\s/ nocase ascii wide
        // Description: allowing SSH incoming connections (critical on DC)
        // Reference: N/A
        $string97 = /New\-NetFirewallRule\s.{0,1000}\s\-Enabled\sTrue\s\-Direction\sInbound\s\-Protocol\sTCP\s\-Action\sAllow\s\-LocalPort\s22/ nocase ascii wide
        // Description: Powershell reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string98 = /New\-Object\sSystem\.Net\.Sockets\.TCPClient\(.{0,1000}\$stream\s\=\s\$client\.GetStream\(\).{0,1000}\[byte\[\]\]\$bytes\s\=\s0\.\.65535/ nocase ascii wide
        // Description: Execution Policy Bypass evasion
        // Reference: N/A
        $string99 = /powershell\s\?encodedcommand\s\$env\:PSExecutionPolicyPreference\=\\"bypass\\"/ nocase ascii wide
        // Description: clearing powershell history
        // Reference: N/A
        $string100 = "powershell -c \"Clear-History\"" nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string101 = /powershell\s\-c\s.{0,1000}\\windows\\system32\\inetsrv\\appcmd\.exe\slist\sapppool\s\/\@t\:/ nocase ascii wide
        // Description: clearing powershell history
        // Reference: N/A
        $string102 = "powershell -c clear" nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string103 = /powershell\sNew\-ItemProperty\s\-Path\s.{0,1000}HKLM\:\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force/ nocase ascii wide
        // Description: uninstalls Windows Defender
        // Reference: https://github.com/spicy-bear/Threat-Hunting/blob/2c89b519862672e29547b4db4796caa923044595/95.213.145.101/%D1%81%D0%B8%D1%80/bat/defendermalwar.bat#L7
        $string104 = "powershell Uninstall-WindowsFeature -Name Windows-Defender" nocase ascii wide
        // Description: PowerShell Downgrade Attacks - forces PowerShell to run in version 2.0
        // Reference: N/A
        $string105 = "PowerShell -Version 2 -Command " nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string106 = "powershell -Version 2" nocase ascii wide
        // Description: Windows Defender tampering technique 
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string107 = /powershell.{0,1000}Uninstall\-WindowsFeature\s\-Name\sWindows\-Defender\-GUI/ nocase ascii wide
        // Description: Adversaries may attempt to execute powershell script from known accessible location
        // Reference: N/A
        $string108 = /Powershell\.exe\s\s\-windowstyle\shidden\s\-nop\s\-ExecutionPolicy\sBypass\s\s\-Commmand\s.{0,1000}C\:\\Users\\.{0,1000}\\AppData\\Roaming\\/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string109 = /powershell\.exe\scurl\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string110 = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string111 = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C.{0,1000}invoke_obfuscation/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string112 = /powershell\.exe\sInvoke\-WebRequest\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string113 = /powershell\.exe\siwr\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string114 = /powershell\.exe\s\-noni\s\-nop\s\-w\s1\s\-enc\s/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string115 = /powershell\.exe\s\-NoP\s\-NoL\s\-sta\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Enc\s/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string116 = /powershell\.exe\s\-nop\s\-w\shidden\s\-c\s\\"IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'http\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: PowerShell Downgrade Attacks - forces PowerShell to run in version 2.0
        // Reference: N/A
        $string117 = /PowerShell\.exe\s\-Version\s2\s\-Command\s/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string118 = /powershell\.exe\s\-Version\s2/ nocase ascii wide
        // Description: downloading from IP without domain name
        // Reference: https://www.trendmicro.com/en_us/research/24/b/threat-actor-groups-including-black-basta-are-exploiting-recent-.html
        $string119 = /powershell\.exe\swget\shttp\:\/\/\[0\-9\]\{1\,3\}/ nocase ascii wide
        // Description: downgrading to powershell version 2
        // Reference: N/A
        $string120 = /powershell\.exe\\"\s\-Version\s2/ nocase ascii wide
        // Description: attempts to evade defenses or remove traces of activity by deleting MRUList registry keys
        // Reference: N/A
        $string121 = /reg\sdelete\s.{0,1000}\s\/v\sMRUList\s\/f/ nocase ascii wide
        // Description: Remove  Sophos folders
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string122 = /Remove\-Item\s\-LiteralPath\s\\"C\:\\Program\sFiles\s\(x86\)\\Sophos\\"\s\-Force\s\-Recurse/ nocase ascii wide
        // Description: Remove  Sophos folders
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string123 = /Remove\-Item\s\-LiteralPath\s\\"C\:\\Program\sFiles\\Sophos\\"\s\-Force\s\-Recurse/ nocase ascii wide
        // Description: Remove  Sophos folders
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string124 = /Remove\-Item\s\-LiteralPath\s\\"C\:\\Program\sFiles\\Sophos.{0,1000}\\"\s\-Force\s\-Recurse/ nocase ascii wide
        // Description: Remove  Sophos folders
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string125 = /Remove\-Item\s\-LiteralPath\s\\"C\:\\ProgramData\\Sophos\\"\s\-Force\s\-Recurse/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string126 = /Remove\-ItemProperty\s\-Path\s\\"HKLM\:\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels\\"\s\-Name\s\\"DisableDevTunnelsInVisualStudio\\"/ nocase ascii wide
        // Description: attempts to evade defenses or remove traces of activity by deleting MRUList registry keys
        // Reference: N/A
        $string127 = /Remove\-ItemProperty\s\-Path.{0,1000}\s\-Name\sMRUList\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string128 = /Remove\-ItemProperty.{0,1000}HKLM\:\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels.{0,1000}DisableDevTunnelsInVisualStudio/ nocase ascii wide
        // Description: list AV products with powershell
        // Reference: N/A
        $string129 = /root\/SecurityCenter2.{0,1000}\s\-ClassName\sAntiVirusProduct/ nocase ascii wide
        // Description: AMSI bypass obfuscation pattern
        // Reference: N/A
        $string130 = /S\`eT\-It\`em\s\(\s\'V\'\+\'aR\'\s\+\s\s\'IA\'\s\+\s\(\'blE\:1\'\+\'q2\'\)/ nocase ascii wide
        // Description: AD module Logon Script from remote IP
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string131 = /Set\-ADObject\s\-SamAccountName\s.{0,1000}\s\-PropertyName\sscriptpath\s\-PropertyValue\s.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Clearing the clipboard is a deliberate attempt to cover tracks and make the attack less detectable
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string132 = "Set-Clipboard -Value ' '" nocase ascii wide
        // Description: Clearing the clipboard is a deliberate attempt to cover tracks and make the attack less detectable
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string133 = "Set-Clipboard -Value ''" nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https[://]87[.]120[.]120[.]56/crypt/xx.ps1
        $string134 = /Set\-ItemProperty.{0,1000}HKLM\:\\SOFTWARE\\Policies\\Microsoft\\VisualStudio\\Devtunnels.{0,1000}DisableDevTunnelsInVisualStudio.{0,1000}0/ nocase ascii wide
        // Description: Disable IPS
        // Reference: N/A
        $string135 = /Set\-MPPreference\s\-DisableIntrusionPreventionSystem\s\$true/ nocase ascii wide
        // Description: Disable scanning all downloaded files and attachments
        // Reference: N/A
        $string136 = /Set\-MpPreference\s\-DisableIOAVProtection\s\$true/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string137 = /Set\-MpPreference\s\-DisableRealtimeMonitoring\s\$true/ nocase ascii wide
        // Description: Disable AMSI (set to 0 to enable)
        // Reference: N/A
        $string138 = "Set-MpPreference -DisableScriptScanning 1 " nocase ascii wide
        // Description: exclude exe file extensions from AV detections
        // Reference: https://github.com/Akabanwa-toma/hacke/blob/aaebb5cb188eb3a17bebfedfbde6b354e5522b92/installer.bat#L29C21-L29C63
        $string139 = "Set-MpPreference -ExclusionExtension exe" nocase ascii wide
        // Description: openssh server is used (critical on DC - must not be installed)
        // Reference: N/A
        $string140 = "Set-Service -Name sshd -StartupType 'Automatic'" nocase ascii wide
        // Description: openssh server is used (critical on DC - must not be installed)
        // Reference: N/A
        $string141 = "Start-Service sshd" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string142 = "Stop-Process -Name \"Sophos " nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string143 = "Stop-Process -Name \"SQL Backups\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string144 = "Stop-Process -Name \"SQLsafe Backup Service\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string145 = /Stop\-Process\s\-Name\s\\"storagecraft\simagemanager.{0,1000}\\"/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string146 = "Stop-Process -Name \"Symantec System Recovery\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string147 = "Stop-Process -Name \"Veeam Backup Catalog Data Service\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string148 = "Stop-Process -Name \"Zoolz 2 Service\"" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string149 = "Stop-Process -Name acronisagent" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string150 = "Stop-Process -Name AcronisAgent" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string151 = "Stop-Process -Name acrsch2svc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string152 = "Stop-Process -Name AcrSch2Svc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string153 = "Stop-Process -Name agntsvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string154 = "Stop-Process -Name Antivirus" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string155 = "Stop-Process -Name ARSM /y" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string156 = "Stop-Process -Name arsm" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string157 = "Stop-Process -Name AVP" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string158 = "Stop-Process -Name backp" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string159 = "Stop-Process -Name backup" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string160 = "Stop-Process -Name BackupExec" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string161 = "Stop-Process -Name BackupExecAgent" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string162 = "Stop-Process -Name bedbg /y" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string163 = "Stop-Process -Name cbservi" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string164 = "Stop-Process -Name cbvscserv" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string165 = "Stop-Process -Name DCAgent" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string166 = "Stop-Process -Name EhttpSrv" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string167 = "Stop-Process -Name ekrn" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string168 = "Stop-Process -Name EPSecurityService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string169 = "Stop-Process -Name EPUpdateService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string170 = "Stop-Process -Name EsgShKernel" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string171 = "Stop-Process -Name ESHASRV" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string172 = "Stop-Process -Name FA_Scheduler" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string173 = "Stop-Process -Name IMAP4Svc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string174 = "Stop-Process -Name KAVFS" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string175 = "Stop-Process -Name KAVFSGT" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string176 = "Stop-Process -Name kavfsslp" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string177 = "Stop-Process -Name klnagent" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string178 = "Stop-Process -Name macmnsvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string179 = "Stop-Process -Name masvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string180 = "Stop-Process -Name MBAMService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string181 = "Stop-Process -Name MBEndpointAgent" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string182 = "Stop-Process -Name McAfeeEngineService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string183 = "Stop-Process -Name McAfeeFramework" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string184 = "Stop-Process -Name McAfeeFrameworkMcAfeeFramework" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string185 = "Stop-Process -Name McShield" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string186 = "Stop-Process -Name mfefire" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string187 = "Stop-Process -Name mfemms" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string188 = "Stop-Process -Name mfevtp" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string189 = "Stop-Process -Name mozyprobackup" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string190 = "Stop-Process -Name MsDtsServer" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string191 = "Stop-Process -Name MsDtsServer100" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string192 = "Stop-Process -Name MsDtsServer110" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string193 = /Stop\-Process\s\-Name\smsftesql\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string194 = /Stop\-Process\s\-Name\sMSOLAP\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string195 = /Stop\-Process\s\-Name\sMSOLAP\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string196 = /Stop\-Process\s\-Name\sMSOLAP\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string197 = /Stop\-Process\s\-Name\sMSOLAP\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string198 = /Stop\-Process\s\-Name\sMSSQL\$BKUPEXEC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string199 = /Stop\-Process\s\-Name\sMSSQL\$ECWDB2/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string200 = /Stop\-Process\s\-Name\sMSSQL\$PRACTICEMGT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string201 = /Stop\-Process\s\-Name\sMSSQL\$PRACTTICEBGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string202 = /Stop\-Process\s\-Name\sMSSQL\$PROD/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string203 = /Stop\-Process\s\-Name\sMSSQL\$PROFXENGAGEMENT/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string204 = /Stop\-Process\s\-Name\sMSSQL\$SBSMONITORING/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string205 = /Stop\-Process\s\-Name\sMSSQL\$SHAREPOINT/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string206 = /Stop\-Process\s\-Name\sMSSQL\$SOPHOS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string207 = /Stop\-Process\s\-Name\sMSSQL\$SQL_2008/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string208 = /Stop\-Process\s\-Name\sMSSQL\$SQLEXPRESS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string209 = /Stop\-Process\s\-Name\sMSSQL\$SYSTEM_BGC/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string210 = /Stop\-Process\s\-Name\sMSSQL\$TPS/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string211 = /Stop\-Process\s\-Name\sMSSQL\$TPSAMA/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string212 = /Stop\-Process\s\-Name\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string213 = /Stop\-Process\s\-Name\sMSSQL\$VEEAMSQL/ nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string214 = "Stop-Process -Name sacsvr" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string215 = "Stop-Process -Name SAVAdminService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string216 = "Stop-Process -Name SAVService" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string217 = "Stop-Process -Name shadowprotectsvc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string218 = "Stop-Process -Name ShMonitor" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string219 = "Stop-Process -Name Smcinst" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string220 = "Stop-Process -Name SmcService" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string221 = "Stop-Process -Name sms_site_sql_backup" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string222 = "Stop-Process -Name SntpService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string223 = "Stop-Process -Name sophossps" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string224 = "Stop-Process -Name spxservice" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string225 = "Stop-Process -Name sqbcoreservice" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string226 = /Stop\-Process\s\-Name\sSQLAgent\$SOPH/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string227 = /Stop\-Process\s\-Name\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string228 = /Stop\-Process\s\-Name\sSQLAgent\$VEEAMSQL/ nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string229 = "Stop-Process -Name stc_endpt_svc" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string230 = "Stop-Process -Name stop SepMasterService" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string231 = "Stop-Process -Name svcGenericHost" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string232 = "Stop-Process -Name swi_filter" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string233 = "Stop-Process -Name swi_service" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string234 = "Stop-Process -Name swi_update" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string235 = "Stop-Process -Name swi_update_64" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string236 = "Stop-Process -Name TmCCSF" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string237 = "Stop-Process -Name tmlisten" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string238 = "Stop-Process -Name TrueKey" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string239 = "Stop-Process -Name TrueKeyScheduler" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string240 = "Stop-Process -Name TrueKeyServiceHel" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string241 = "Stop-Process -Name vapiendpoint" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string242 = "Stop-Process -Name VeeamBackupSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string243 = "Stop-Process -Name VeeamBrokerSvc " nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string244 = "Stop-Process -Name VeeamCatalogSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string245 = "Stop-Process -Name VeeamCloudSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string246 = "Stop-Process -Name VeeamDeploymentService" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string247 = "Stop-Process -Name VeeamDeploySvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string248 = "Stop-Process -Name VeeamDeploySvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string249 = "Stop-Process -Name VeeamEnterpriseManagerSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string250 = "Stop-Process -Name VeeamHvIntegrationSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string251 = "Stop-Process -Name VeeamMountSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string252 = "Stop-Process -Name VeeamNFSSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string253 = "Stop-Process -Name VeeamRESTSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string254 = "Stop-Process -Name VeeamTransportSvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string255 = "Stop-Process -Name vsnapvss" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string256 = "Stop-Process -Name vssvc" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string257 = "Stop-Process -Name wbengine" nocase ascii wide
        // Description: stopping backup services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string258 = "Stop-Process -Name wbengine" nocase ascii wide
        // Description: stopping AV services
        // Reference: https://github.com/TheParmak/conti-leaks-englished/blob/45d49307f347aff10e0f088af25142f8929b4c4f/anonfile_dumps/31.txt#L236
        $string259 = "Stop-Process -Name WRSVC" nocase ascii wide
        // Description: suspicious pattern used by poshC2 and many other offensive tools (false positives possible)
        // Reference: N/A
        $string260 = /System\.IO\.MemoryStream\(\,\[System\.Convert\]\:\:FromBase64String\(/ nocase ascii wide
        // Description: powershell command to uninstall defender AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string261 = "Uninstall-WindowsFeature -Name Windows-Defender" nocase ascii wide

    condition:
        any of them
}
