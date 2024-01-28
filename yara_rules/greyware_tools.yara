rule action1_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'action1' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "action1"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string1_action1_greyware_tool_keyword = /\/action1_agent\(My_Organization\)\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string2_action1_greyware_tool_keyword = /\\Action1\\7z\.dll/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string3_action1_greyware_tool_keyword = /\\Action1\\Agent\\Certificate/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string4_action1_greyware_tool_keyword = /\\Action1\\CrashDumps/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string5_action1_greyware_tool_keyword = /\\Action1\\package_downloads/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string6_action1_greyware_tool_keyword = /\\Action1\\scripts\\Run_PowerShell_/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string7_action1_greyware_tool_keyword = /\\action1_agent\(My_Organization\)\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string8_action1_greyware_tool_keyword = /\\ACTION1_AGENT\.EXE\-/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string9_action1_greyware_tool_keyword = /\\action1_log_.{0,1000}\.log/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string10_action1_greyware_tool_keyword = /\\Windows\\Action1\\scripts\\/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string11_action1_greyware_tool_keyword = /_renamed_by_Action1/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string12_action1_greyware_tool_keyword = /a1\-server\-prod\-even\.action1\.com/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string13_action1_greyware_tool_keyword = /Action1\sCorporation/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string14_action1_greyware_tool_keyword = /Action1\sEndpoint\sSecurity/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string15_action1_greyware_tool_keyword = /Action1.{0,1000}\'DestinationPort\'\>22543/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string16_action1_greyware_tool_keyword = /Action1\\batch_data\\Run_Script__/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string17_action1_greyware_tool_keyword = /Action1\\first_install\.tmp/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string18_action1_greyware_tool_keyword = /Action1\\what_is_this\.txt/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string19_action1_greyware_tool_keyword = /action1_agent\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string20_action1_greyware_tool_keyword = /action1_agent\.exe\.connection/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string21_action1_greyware_tool_keyword = /action1_remote\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string22_action1_greyware_tool_keyword = /action1_update\.exe/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string23_action1_greyware_tool_keyword = /C:\\Windows\\Action1\\/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string24_action1_greyware_tool_keyword = /C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Action1/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string25_action1_greyware_tool_keyword = /\'Company\'\>Action1\sCorporation/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string26_action1_greyware_tool_keyword = /CurrentControlSet\\Services\\A1Agent/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string27_action1_greyware_tool_keyword = /https:\/\/app\.action1\.com\/agent\/.{0,1000}\/Windows\/.{0,1000}\.msi/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string28_action1_greyware_tool_keyword = /InventoryApplicationFile\\action1_agent\.ex/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string29_action1_greyware_tool_keyword = /InventoryApplicationFile\\action1_remote\.e/ nocase ascii wide
        // Description: Action1 remote administration tool abused buy attacker
        // Reference: https://app.action1.com/
        $string30_action1_greyware_tool_keyword = /server\.action1\.com/ nocase ascii wide

    condition:
        any of them
}


rule Adblock_Office_VPN_Proxy_Server_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Adblock Office VPN Proxy Server' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adblock Office VPN Proxy Server"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Adblock_Office_VPN_Proxy_Server_greyware_tool_keyword = /lcmammnjlbmlbcaniggmlejfjpjagiia/ nocase ascii wide

    condition:
        any of them
}


rule adexplorer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adexplorer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adexplorer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string1_adexplorer_greyware_tool_keyword = /adexplorer\.exe/ nocase ascii wide
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string2_adexplorer_greyware_tool_keyword = /adexplorer\.zip/ nocase ascii wide
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string3_adexplorer_greyware_tool_keyword = /adexplorer64\.exe/ nocase ascii wide
        // Description: Active Directory Explorer (AD Explorer) is an advanced Active Directory (AD) viewer and editor. You can use AD Explorer to easily navigate an AD database. It can be abused by malicious actors
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer
        $string4_adexplorer_greyware_tool_keyword = /adexplorer64a\.exe/ nocase ascii wide

    condition:
        any of them
}


rule adfind_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adfind' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfind"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string1_adfind_greyware_tool_keyword = /\sdclist\s/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string2_adfind_greyware_tool_keyword = /\s\-sc\strustdump/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string3_adfind_greyware_tool_keyword = /adfind\s\-f\s/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string4_adfind_greyware_tool_keyword = /adfind\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string5_adfind_greyware_tool_keyword = /adfind\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string6_adfind_greyware_tool_keyword = /adfind\.bat/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string7_adfind_greyware_tool_keyword = /adfind\.exe\s\-f\sobjectclass\=trusteddomain/ nocase ascii wide
        // Description: query domain trusts with adfind
        // Reference: N/A
        $string8_adfind_greyware_tool_keyword = /adfind\.exe\s\-sc\strustdmp/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string9_adfind_greyware_tool_keyword = /adfind\.exe/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://www.joeware.net/freetools/tools/adfind/usage.htm
        $string10_adfind_greyware_tool_keyword = /AdFind\.zip/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string11_adfind_greyware_tool_keyword = /computers_pwdnotreqd/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string12_adfind_greyware_tool_keyword = /name\=.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: Adfind is a command-line tool often used by administrators for Active Directory queries. However. attackers can misuse it to gather valuable information about the network environment. including user accounts. group memberships. domain controllers. and domain trusts. This gathered intelligence can aid in lateral movement. privilege escalation. or even data exfiltration. Such reconnaissance activities often precede more damaging attacks.
        // Reference: https://thedfirreport.com/2022/08/08/bumblebee-roasts-its-way-to-domain-admin/
        $string13_adfind_greyware_tool_keyword = /tools\/adfind/ nocase ascii wide

    condition:
        any of them
}


rule adget_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adget' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adget"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: gather valuable informations about the AD environment
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string1_adget_greyware_tool_keyword = /\\ADGet\.exe/ nocase ascii wide

    condition:
        any of them
}


rule AdGuard_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AdGuard VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdGuard VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_AdGuard_VPN_greyware_tool_keyword = /hhdobjgopfphlmjbmnpglhfcgppchgje/ nocase ascii wide

    condition:
        any of them
}


rule adiskreader_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adiskreader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adiskreader"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string1_adiskreader_greyware_tool_keyword = /\#\sadiskreader\s/ nocase ascii wide
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string2_adiskreader_greyware_tool_keyword = /\\adiskreader\\/ nocase ascii wide
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string3_adiskreader_greyware_tool_keyword = /adiskreader\.disks\.raw/ nocase ascii wide
        // Description: Async Python library to parse local and remote disk images
        // Reference: https://github.com/skelsec/adiskreader
        $string4_adiskreader_greyware_tool_keyword = /adiskreader\.disks\.vhdx/ nocase ascii wide

    condition:
        any of them
}


rule adrecon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'adrecon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adrecon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string1_adrecon_greyware_tool_keyword = /ADRecon\s\-OutputDir\s/ nocase ascii wide
        // Description: ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.
        // Reference: https://github.com/adrecon/ADRecon
        $string2_adrecon_greyware_tool_keyword = /ADRecon\.ps1/ nocase ascii wide

    condition:
        any of them
}


rule advanced_port_scanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'advanced port scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced port scanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string1_advanced_port_scanner_greyware_tool_keyword = /\/lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string2_advanced_port_scanner_greyware_tool_keyword = /\\Advanced\sPort\sScanner\sPortable\\/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string3_advanced_port_scanner_greyware_tool_keyword = /\\lansearch\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string4_advanced_port_scanner_greyware_tool_keyword = /\\Temp\\2\\Advanced\sPort\sScanner\s2\\/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string5_advanced_port_scanner_greyware_tool_keyword = /advanced_port_scanner\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string6_advanced_port_scanner_greyware_tool_keyword = /advanced_port_scanner_console\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string7_advanced_port_scanner_greyware_tool_keyword = /lansearch\.exe\s/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string8_advanced_port_scanner_greyware_tool_keyword = /lansearchpro_portable\.zip/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string9_advanced_port_scanner_greyware_tool_keyword = /lansearchpro_setup\.exe/ nocase ascii wide
        // Description: port scanner tool abused by ransomware actors
        // Reference: https://www.advanced-port-scanner.com/
        $string10_advanced_port_scanner_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Advanced\sPort\sScanner\\/ nocase ascii wide

    condition:
        any of them
}


rule advanced_ip_scanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "advanced-ip-scanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string1_advanced_ip_scanner_greyware_tool_keyword = /\.exe\s\/s:ip_ranges\.txt\s\/f:scan_results\.txt/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string2_advanced_ip_scanner_greyware_tool_keyword = /\\Local\\Temp\\Advanced\sIP\sScanner\s2\\/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string3_advanced_ip_scanner_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Advanced\sIP\sScanner\\/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string4_advanced_ip_scanner_greyware_tool_keyword = /\\Programs\\Advanced\sIP\sScanner\sPortable\\/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string5_advanced_ip_scanner_greyware_tool_keyword = /Advanced\sIP\sScanner/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string6_advanced_ip_scanner_greyware_tool_keyword = /advanced_ip_scanner/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string7_advanced_ip_scanner_greyware_tool_keyword = /Advanced_IP_Scanner.{0,1000}\.exe/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string8_advanced_ip_scanner_greyware_tool_keyword = /advanced_ip_scanner_console\.exe/ nocase ascii wide
        // Description: The program shows all network devices. gives you access to shared folders. provides remote control of computers (via RDP and Radmin) and can even remotely switch computers off. It is easy to use and runs as a portable edition (abused by TA)
        // Reference: https://www.huntandhackett.com/blog/advanced-ip-scanner-the-preferred-scanner-in-the-apt-toolbox
        $string9_advanced_ip_scanner_greyware_tool_keyword = /https:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}


rule AdvancedRun_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AdvancedRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdvancedRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: nirsoft tool  - Run a program with different settings that you choose
        // Reference: https://medium.com/s2wblog/analysis-of-destructive-malware-whispergate-targeting-ukraine-9d5d158f19f3
        $string1_AdvancedRun_greyware_tool_keyword = /AdvancedRun\.exe\s\/EXEFilename\s.{0,1000}\\sc\.exe.{0,1000}stop\sWinDefend/ nocase ascii wide

    condition:
        any of them
}


rule aeroadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'aeroadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "aeroadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string1_aeroadmin_greyware_tool_keyword = /\saeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string2_aeroadmin_greyware_tool_keyword = /\/aeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string3_aeroadmin_greyware_tool_keyword = /\\AeroAdmin\s.{0,1000}_Portable\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string4_aeroadmin_greyware_tool_keyword = /\\aeroadmin\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string5_aeroadmin_greyware_tool_keyword = /\\Aeroadmin\.lnk/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string6_aeroadmin_greyware_tool_keyword = /\\Aeroadmin\\black\.bmp/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string7_aeroadmin_greyware_tool_keyword = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string8_aeroadmin_greyware_tool_keyword = /\\CurrentControlSet\\Services\\AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string9_aeroadmin_greyware_tool_keyword = /\\InventoryApplicationFile\\aeroadmin/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string10_aeroadmin_greyware_tool_keyword = /\\ProgramData\\Aeroadmin\\/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string11_aeroadmin_greyware_tool_keyword = /2ef8a13faa44755fab1ac6fb3665cc78f7e7b451/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string12_aeroadmin_greyware_tool_keyword = /Aeroadmin\sLLC/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string13_aeroadmin_greyware_tool_keyword = /AeroAdmin\sPRO\s\-\sremote\sdesktop\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string14_aeroadmin_greyware_tool_keyword = /AeroAdmin\sPRO\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string15_aeroadmin_greyware_tool_keyword = /AeroAdmin\sv4\..{0,1000}\s\(/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string16_aeroadmin_greyware_tool_keyword = /AeroAdmin\.cpp/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string17_aeroadmin_greyware_tool_keyword = /AEROADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string18_aeroadmin_greyware_tool_keyword = /Aeroadmin\\Screenshots/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string19_aeroadmin_greyware_tool_keyword = /AeroAdmin_2\.exe/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string20_aeroadmin_greyware_tool_keyword = /AeroadminService/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string21_aeroadmin_greyware_tool_keyword = /auth.{0,1000}\.aeroadmin\.com/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string22_aeroadmin_greyware_tool_keyword = /auth11\.aeroadmin\.com/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string23_aeroadmin_greyware_tool_keyword = /DEFAULT\\Software\\AeroAdmin/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string24_aeroadmin_greyware_tool_keyword = /EE54577067550559C4711C9E5E10435807F9DEEE9A5ADB4409CB60A6B0108700/ nocase ascii wide
        // Description: RMM software - full remote control / file transfer
        // Reference: https://ulm.aeroadmin.com/AeroAdmin.exe
        $string25_aeroadmin_greyware_tool_keyword = /ulm\.aeroadmin\.com\// nocase ascii wide

    condition:
        any of them
}


rule AlanFramework_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AlanFramework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AlanFramework"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string1_AlanFramework_greyware_tool_keyword = /http.{0,1000}:\/\/127\.0\.0\.1:8081/ nocase ascii wide
        // Description: Alan Framework is a post-exploitation framework useful during red-team activities.
        // Reference: https://github.com/enkomio/AlanFramework
        $string2_AlanFramework_greyware_tool_keyword = /http.{0,1000}:\/\/localhost:8081/ nocase ascii wide

    condition:
        any of them
}


rule Ammyy_Admin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string1_Ammyy_Admin_greyware_tool_keyword = /\\aa_nts\.dll/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string2_Ammyy_Admin_greyware_tool_keyword = /\\AA_v3\.exe/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string3_Ammyy_Admin_greyware_tool_keyword = /\\AA_v3\.log/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string4_Ammyy_Admin_greyware_tool_keyword = /\\AMMYY\\access\.log/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string5_Ammyy_Admin_greyware_tool_keyword = /\\ControlSet001\\Control\\SafeBoot\\Network\\AmmyyAdmin_/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string6_Ammyy_Admin_greyware_tool_keyword = /\\ProgramData\\AMMYY\\/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string7_Ammyy_Admin_greyware_tool_keyword = /\\SOFTWARE\\Ammyy\\Admin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string8_Ammyy_Admin_greyware_tool_keyword = /AA_v3\.exe.{0,1000}\s\-elevated/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string9_Ammyy_Admin_greyware_tool_keyword = /AA_v3\.exe.{0,1000}\s\-service\s\-lunch/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string10_Ammyy_Admin_greyware_tool_keyword = /Ammyy\sAdmin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string11_Ammyy_Admin_greyware_tool_keyword = /Ammyy\sLLC/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string12_Ammyy_Admin_greyware_tool_keyword = /PUA:Win32\/AmmyyAdmin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string13_Ammyy_Admin_greyware_tool_keyword = /rl\.ammyy\.com\// nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string14_Ammyy_Admin_greyware_tool_keyword = /SPR\/Ammyy\.R/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string15_Ammyy_Admin_greyware_tool_keyword = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string16_Ammyy_Admin_greyware_tool_keyword = /www\.ammyy\.com\/files\/v/ nocase ascii wide

    condition:
        any of them
}


rule anonfiles_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'anonfiles.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anonfiles.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_anonfiles_com_greyware_tool_keyword = /https:\/\/anonfiles\.com\/.{0,1000}\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2_anonfiles_com_greyware_tool_keyword = /https:\/\/api\.anonfiles\.com\/upload/ nocase ascii wide

    condition:
        any of them
}


rule Anonymous_Proxy_Vpn_Browser_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Anonymous Proxy Vpn Browser' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Anonymous Proxy Vpn Browser"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Anonymous_Proxy_Vpn_Browser_greyware_tool_keyword = /lklekjodgannjcccdlbicoamibgbdnmi/ nocase ascii wide

    condition:
        any of them
}


rule anydesk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'anydesk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anydesk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string1_anydesk_greyware_tool_keyword = /\\adprinterpipe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string2_anydesk_greyware_tool_keyword = /\\AnyDesk\s\(1\)\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string3_anydesk_greyware_tool_keyword = /\\AnyDesk\.exe/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string4_anydesk_greyware_tool_keyword = /\\AnyDesk\\connection_trace\.txt/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string5_anydesk_greyware_tool_keyword = /\\anydesk\\printer_driver/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string6_anydesk_greyware_tool_keyword = /\\AnyDesk\\service\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string7_anydesk_greyware_tool_keyword = /\\AnyDeskPrintDriver\.cat/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string8_anydesk_greyware_tool_keyword = /\\anydeskprintdriver\.inf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string9_anydesk_greyware_tool_keyword = /\\AppData\\Roaming\\AnyDesk\\system\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string10_anydesk_greyware_tool_keyword = /\\AppData\\Roaming\\AnyDesk\\user\.conf/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string11_anydesk_greyware_tool_keyword = /\\Prefetch\\ANYDESK\.EXE/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string12_anydesk_greyware_tool_keyword = /AnyDesk\sSoftware\sGmbH/ nocase ascii wide
        // Description: setting the AnyDesk service password manually
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string13_anydesk_greyware_tool_keyword = /anydesk\.exe\s\-\-set\-password/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string14_anydesk_greyware_tool_keyword = /boot\.net\.anydesk\.com/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string15_anydesk_greyware_tool_keyword = /C:\\Program\sFiles\s\(x86\)\\AnyDesk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string16_anydesk_greyware_tool_keyword = /Desktop\\AnyDesk\.lnk/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string17_anydesk_greyware_tool_keyword = /HKCR\\\.anydesk\\/ nocase ascii wide
        // Description: Anydesk RMM usage
        // Reference: https://anydesk.com/
        $string18_anydesk_greyware_tool_keyword = /relay\-.{0,1000}\.net\.anydesk\.com/ nocase ascii wide

    condition:
        any of them
}


rule anymailfinder_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'anymailfinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "anymailfinder"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attackers to find informations about a company users
        // Reference: https://anymailfinder.com
        $string1_anymailfinder_greyware_tool_keyword = /https:\/\/anymailfinder\.com\/search\// nocase ascii wide

    condition:
        any of them
}


rule apkfold_free_vpn_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'apkfold free vpn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "apkfold free vpn"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_apkfold_free_vpn_greyware_tool_keyword = /jbnmpdkcfkochpanomnkhnafobppmccn/ nocase ascii wide

    condition:
        any of them
}


rule APT_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'APT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - backdoor apt execute a command when invoking apt
        // Reference: N/A
        $string1_APT_greyware_tool_keyword = /APT::Update::Pre\-Invoke\s.{0,1000}}/ nocase ascii wide

    condition:
        any of them
}


rule assoc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'assoc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "assoc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: will return the file association for file extensions that include the string =cm - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string1_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\s.{0,1000}\=cm/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string2_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\s.{0,1000}lCmd/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string3_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\s.{0,1000}mdf/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string4_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\s.{0,1000}s1x/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string =cm - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string5_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\s\=cm/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string lCmd - hidden objectif is to find .cdxml association
        // Reference: N/A
        $string6_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\slCmd/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string mdf - hidden objectif is to find cmdfile association
        // Reference: N/A
        $string7_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\smdf/ nocase ascii wide
        // Description: will return the file association for file extensions that include the string s1x - hidden objectif is to find .ps1xml association
        // Reference: N/A
        $string8_assoc_greyware_tool_keyword = /assoc\s.{0,1000}findstr\ss1x/ nocase ascii wide

    condition:
        any of them
}


rule Astar_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Astar VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Astar VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Astar_VPN_greyware_tool_keyword = /jajilbjjinjmgcibalaakngmkilboobh/ nocase ascii wide

    condition:
        any of them
}


rule Atera_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Atera' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Atera"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string1_Atera_greyware_tool_keyword = /\/Agent\/AcknowledgeCommands\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string2_Atera_greyware_tool_keyword = /\/Agent\/GetCommandsFallback\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string3_Atera_greyware_tool_keyword = /\/Agent\/GetEnvironmentStatus\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string4_Atera_greyware_tool_keyword = /\/Agent\/GetRecurringPackages\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string5_Atera_greyware_tool_keyword = /\\AlphaControlAgent\\obj\\Release\\AteraAgent\.pdb/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string6_Atera_greyware_tool_keyword = /\\atera_agent\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string7_Atera_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Atera\sNetworks/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string8_Atera_greyware_tool_keyword = /\\Program\sFiles\\Atera\sNetworks/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string9_Atera_greyware_tool_keyword = /\\TEMP\\AteraUpgradeAgentPackage\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string10_Atera_greyware_tool_keyword = /acontrol\.atera\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string11_Atera_greyware_tool_keyword = /agent\-api\.atera\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string12_Atera_greyware_tool_keyword = /AgentPackageInternalPooler\\log\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string13_Atera_greyware_tool_keyword = /AgentPackageRunCommandInteractive\\log\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string14_Atera_greyware_tool_keyword = /AlphaControlAgent\.CloudLogsManager\+\<\>/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string15_Atera_greyware_tool_keyword = /atera_del\.bat/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string16_Atera_greyware_tool_keyword = /atera_del2\.bat/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string17_Atera_greyware_tool_keyword = /AteraAgent.{0,1000}AgentPackageRunCommandInteractive\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string18_Atera_greyware_tool_keyword = /AteraSetupLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string19_Atera_greyware_tool_keyword = /http.{0,1000}\/agent\-api\-.{0,1000}\.atera\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string20_Atera_greyware_tool_keyword = /Monitoring\s\&\sManagement\sAgent\sby\sATERA/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string21_Atera_greyware_tool_keyword = /SOFTWARE\\ATERA\sNetworks\\AlphaAgent/ nocase ascii wide

    condition:
        any of them
}


rule attrib_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'attrib' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "attrib"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: command aiming to hide a file.  It can be performed with attrib.exe on a WINDOWS machine with command option +h 
        // Reference: N/A
        $string1_attrib_greyware_tool_keyword = /\\attrib\.exe.{0,1000}\s\+H\s/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string2_attrib_greyware_tool_keyword = /attrib\s\+s\s\+h\sdesktop\.ini/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string3_attrib_greyware_tool_keyword = /echo\s\[\.ShellClassInfo\]\s\>\sdesktop\.ini/ nocase ascii wide
        // Description: NTLM Leak via Desktop.ini
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string4_attrib_greyware_tool_keyword = /echo\sIconResource\=\\\\.{0,1000}\\.{0,1000}\s\>\>\sdesktop\.ini/ nocase ascii wide

    condition:
        any of them
}


rule AutoSUID_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'AutoSUID' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoSUID"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string1_AutoSUID_greyware_tool_keyword = /\spwn_tclsh\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string2_AutoSUID_greyware_tool_keyword = /\sWe\shave\sfound\sat\sleast\s.{0,1000}\spotential\sSUID\sexploitable\sfile\(s\)/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string3_AutoSUID_greyware_tool_keyword = /\.\/capsh\s\-\-gid\=0\s\-\-uid\=0\s\-\-/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string4_AutoSUID_greyware_tool_keyword = /\.\/chroot\s\/\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string5_AutoSUID_greyware_tool_keyword = /\.\/env\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string6_AutoSUID_greyware_tool_keyword = /\.\/expect\s\-c\s\'spawn\s\/bin\/sh\s\-p\;interact\'/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string7_AutoSUID_greyware_tool_keyword = /\.\/flock\s\-u\s\/\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string8_AutoSUID_greyware_tool_keyword = /\.\/nice\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string9_AutoSUID_greyware_tool_keyword = /\.\/rview\s\-c\s\':py3\simport\sos.{0,1000}os\.execl\(\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string10_AutoSUID_greyware_tool_keyword = /\/ld\.so\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string11_AutoSUID_greyware_tool_keyword = /\/perf\sstat\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string12_AutoSUID_greyware_tool_keyword = /\/perl\s\-e\s\'exec\s\\\"\/bin\/sh\\\"/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string13_AutoSUID_greyware_tool_keyword = /\/pwn_tclsh\.me/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string14_AutoSUID_greyware_tool_keyword = /\/rvim\s\-c\s\':py3\simport\sos.{0,1000}os\.execl\(\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string15_AutoSUID_greyware_tool_keyword = /\/sshpass\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string16_AutoSUID_greyware_tool_keyword = /\/stdbuf\s\-i0\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string17_AutoSUID_greyware_tool_keyword = /\/unshare\s\-r\s\/bin\/sh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string18_AutoSUID_greyware_tool_keyword = /\/view\s\-c\s\':py3\simport\sos.{0,1000}os\.execl\(\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string19_AutoSUID_greyware_tool_keyword = /\/watch\s\-x\ssh\s\-c\s\'reset.{0,1000}\sexec\ssh\s1\>\&0\s2\>\&0/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string20_AutoSUID_greyware_tool_keyword = /agetty\s\-o\s\-p\s\-l\s\/bin\/sh\s\-a\sroot\stty/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string21_AutoSUID_greyware_tool_keyword = /cpulimit\s\-l\s100\s\-f\s\-\-\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string22_AutoSUID_greyware_tool_keyword = /dmsetup\screate\sbase\s\<\<EOF.{0,1000}0\s3534848\slinear\s\/dev\/loop0\s94208.{0,1000}\sEOF.{0,1000}\.\/dmsetup\sls\s\-\-exec\s\'\/bin\/sh\s\-p\s\-s/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string23_AutoSUID_greyware_tool_keyword = /docker\srun\s\-v\s\/:\/mnt\s\-\-rm\s\-it\salpine\schroot\s\/mnt\ssh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string24_AutoSUID_greyware_tool_keyword = /emacs\s\-Q\s\-nw\s\-\-eval\s\'\(term\s\\\"\/bin\/sh\s\-p\\\"\)/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string25_AutoSUID_greyware_tool_keyword = /\'exec\s\/bin\/sh\s\-p\s0\<\&1\'\s\>\>\s\\\$TF_AutoSUID_greyware_tool_keyword/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string26_AutoSUID_greyware_tool_keyword = /find\s\.\s\-exec\s\/bin\/sh\s\-p\s\\\;\s\-quit/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string27_AutoSUID_greyware_tool_keyword = /find\s\/\s\-xdev\s\-user\sroot\s\\\(\s\-perm\s\-4000\s\-o\s\-perm\s\-2000\s\-o\s\-perm\s\-6000\s\\\)\s2\>\/dev\/null/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string28_AutoSUID_greyware_tool_keyword = /gdb\s\-nx\s\-ex\s\'python\simport\sos.{0,1000}os\.execl\(\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string29_AutoSUID_greyware_tool_keyword = /genie\s\-c\s\'\/bin\/sh\'/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string30_AutoSUID_greyware_tool_keyword = /gimp\s\-idf\s\-\-batch\-interpreter\=python\-fu\-eval\s\-b\s\'import\sos.{0,1000}\sos\.execl\(.{0,1000}\/bin\/sh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string31_AutoSUID_greyware_tool_keyword = /ionice\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string32_AutoSUID_greyware_tool_keyword = /logsave\s\/dev\/null\s\/bin\/sh\s\-i\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string33_AutoSUID_greyware_tool_keyword = /msgfilter\s\-P\s\/bin\/sh\s\-p\s\-c\s\'\/bin\/sh/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string34_AutoSUID_greyware_tool_keyword = /php\s\-r\s\\\"pcntl_exec\(\'\/bin\/sh\'/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string35_AutoSUID_greyware_tool_keyword = /rsync\s\-e\s\'sh\s\-p\s\-c\s.{0,1000}sh\s0\<\&2\s1\>\&2.{0,1000}127\.0\.0\.1:\/dev\/null/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string36_AutoSUID_greyware_tool_keyword = /strace\s\-o\s\/dev\/null\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string37_AutoSUID_greyware_tool_keyword = /taskset\s1\s\/bin\/sh\s\-p/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string38_AutoSUID_greyware_tool_keyword = /vim\s\-c\s\':py3\simport\sos.{0,1000}\sos\.execl\(\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string39_AutoSUID_greyware_tool_keyword = /vimdiff\s\-c\s\':py3\simport\sos.{0,1000}\sos\.execl\(\\\"\/bin\/sh\\/ nocase ascii wide
        // Description: automate harvesting the SUID executable files and to find a way for further escalating the privileges
        // Reference: https://github.com/IvanGlinkin/AutoSUID
        $string40_AutoSUID_greyware_tool_keyword = /xargs\s\-a\s\/dev\/null\ssh\s\-p/ nocase ascii wide

    condition:
        any of them
}


rule Azino_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Azino VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azino VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Azino_VPN_greyware_tool_keyword = /iolonopooapdagdemdoaihahlfkncfgg/ nocase ascii wide

    condition:
        any of them
}


rule _base64_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'base64' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "base64"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious base64 commands used by the offensive tool traitor and other tools
        // Reference: N/A
        $string1__base64_greyware_tool_keyword = /\|\sbase64\s\-d\s/ nocase ascii wide
        // Description: suspicious base64 commands used by the offensive tool traitor and other tools
        // Reference: N/A
        $string2__base64_greyware_tool_keyword = /base64\s\-d\s\/tmp\// nocase ascii wide

    condition:
        any of them
}


rule bash_keylogger_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bash keylogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash keylogger"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1_bash_keylogger_greyware_tool_keyword = /history\s\-a.{0,1000}\stail\s\-n1\s~\/\.bash_history\s\>\s\/dev\/tcp\/.{0,1000}\// nocase ascii wide

    condition:
        any of them
}


rule bash_port_scan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bash port scan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash port scan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1_bash_port_scan_greyware_tool_keyword = /for\si\sin\s{1\.\.65535}/ nocase ascii wide

    condition:
        any of them
}


rule bash_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bash"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1_bash_greyware_tool_keyword = /bash\s\-c\s.{0,1000}curl\s.{0,1000}\.sh\s\|\sbash/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2_bash_greyware_tool_keyword = /bash\s\-c\s.{0,1000}wget\s.{0,1000}\.sh\s\|\sbash/ nocase ascii wide
        // Description: bash reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3_bash_greyware_tool_keyword = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4_bash_greyware_tool_keyword = /bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string5_bash_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s.{0,1000}bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string6_bash_greyware_tool_keyword = /echo\s.{0,1000}\s\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string7_bash_greyware_tool_keyword = /echo\s.{0,1000}\s\/home\/.{0,1000}\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string8_bash_greyware_tool_keyword = /echo\s.{0,1000}\s\/root\/\.bash_history/ nocase ascii wide
        // Description: add a passwordless user 
        // Reference: N/A
        $string9_bash_greyware_tool_keyword = /echo\s.{0,1000}::0:0::\/root:\/bin\/bash.{0,1000}\s\>\>\/etc\/passwd/ nocase ascii wide
        // Description: Backdooring APT
        // Reference: N/A
        $string10_bash_greyware_tool_keyword = /echo\s.{0,1000}APT::Update::Pre\-Invoke\s.{0,1000}nohup\sncat\s\-lvp\s.{0,1000}\s\-e\s\/bin\/bash\s.{0,1000}\s\>\s\/etc\/apt\/apt\.conf\.d\// nocase ascii wide
        // Description: Backdooring Message of the Day
        // Reference: N/A
        $string11_bash_greyware_tool_keyword = /echo\s.{0,1000}bash\s\-c\s.{0,1000}bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string12_bash_greyware_tool_keyword = /exec\s\/bin\/sh\s0\<\/dev\/tcp\/.{0,1000}\/.{0,1000}1\>\&0\s2\>\&0/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string13_bash_greyware_tool_keyword = /exec\s5\<\>\/dev\/tcp\/.{0,1000}\/.{0,1000}.{0,1000}cat\s\<\&5\s\|\swhile\sread\sline.{0,1000}\sdo\s\$line_bash_greyware_tool_keyword\s2\>\&5\s\>\&5.{0,1000}\sdone/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string14_bash_greyware_tool_keyword = /export\sHISTFILE\=\/dev\/null/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string15_bash_greyware_tool_keyword = /export\sHISTFILESIZE\=0/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string16_bash_greyware_tool_keyword = /export\sHISTFILESIZE\=0/ nocase ascii wide
        // Description: use a space in front of your bash command and it won't be logged with the following option
        // Reference: N/A
        $string17_bash_greyware_tool_keyword = /HISTCONTROL\=ignoredups:ignorespace/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string18_bash_greyware_tool_keyword = /history\s\-c/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: N/A
        $string19_bash_greyware_tool_keyword = /HISTORY\=\/dev\/null/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string20_bash_greyware_tool_keyword = /ln\s\-sf\s\/dev\/null\s.{0,1000}bash_history/ nocase ascii wide
        // Description: Bash Keylogger
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string21_bash_greyware_tool_keyword = /PROMPT_COMMAND\=.{0,1000}history\s\-a.{0,1000}\stail\s.{0,1000}\.bash_history\s\>\s\/dev\/tcp\/127\.0\.0\.1\// nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string22_bash_greyware_tool_keyword = /rm\s\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string23_bash_greyware_tool_keyword = /rm\s\/home\/.{0,1000}\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string24_bash_greyware_tool_keyword = /rm\s\/root\/\.bash_history/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string25_bash_greyware_tool_keyword = /set\shistory\s\+o/ nocase ascii wide
        // Description: Equation Group reverse shell method - simple bash reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string26_bash_greyware_tool_keyword = /sh\s\>\/dev\/tcp\/.{0,1000}\s\<\&1\s2\>\&1/ nocase ascii wide
        // Description: bash reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string27_bash_greyware_tool_keyword = /sh\s\-i\s\>\&\s\/dev\/udp\/.{0,1000}\/.{0,1000}\s0\>\&1/ nocase ascii wide
        // Description: Clear command history in linux which is used for defense evasion. 
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1146/T1146.yaml
        $string28_bash_greyware_tool_keyword = /truncate\s\-s0\s.{0,1000}bash_history\'/ nocase ascii wide
        // Description: Adversaries may attempt to clear or disable the Bash command-line history in an attempt to evade detection or forensic investigations.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_deletion_of_bash_command_line_history.toml
        $string29_bash_greyware_tool_keyword = /unset\sHISTFILE/ nocase ascii wide

    condition:
        any of them
}


rule bashupload_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bashupload.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bashupload.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_bashupload_com_greyware_tool_keyword = /https:\/\/bashupload\.com/ nocase ascii wide

    condition:
        any of them
}


rule bcdedit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bcdedit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bcdedit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Bcdedit is a command-line tool that enables users to view and make changes to boot configuration data (BCD) settings in Windows systems. Adversaries may leverage bcdedit to modify boot settings. such as enabling debug mode or disabling code integrity checks. as a means to bypass security mechanisms and gain persistence on the compromised system. By modifying the boot configuration. adversaries can evade detection and potentially maintain access to the system even after reboots.
        // Reference: N/A
        $string1_bcdedit_greyware_tool_keyword = /bcdedit.{0,1000}\s\/set\s{default}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
        // Description: Bcdedit is a command-line tool that enables users to view and make changes to boot configuration data (BCD) settings in Windows systems. Adversaries may leverage bcdedit to modify boot settings. such as enabling debug mode or disabling code integrity checks. as a means to bypass security mechanisms and gain persistence on the compromised system. By modifying the boot configuration. adversaries can evade detection and potentially maintain access to the system even after reboots.
        // Reference: N/A
        $string2_bcdedit_greyware_tool_keyword = /bcdedit.{0,1000}\s\/set\s{default}\srecoveryenabled\sNo/ nocase ascii wide

    condition:
        any of them
}


rule BelkaVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BelkaVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BelkaVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_BelkaVPN_greyware_tool_keyword = /npgimkapccfidfkfoklhpkgmhgfejhbj/ nocase ascii wide

    condition:
        any of them
}


rule Best_VPN_USA_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Best VPN USA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Best VPN USA"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Best_VPN_USA_greyware_tool_keyword = /ficajfeojakddincjafebjmfiefcmanc/ nocase ascii wide

    condition:
        any of them
}


rule binwalk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'binwalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "binwalk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Binwalk is a fast. easy to use tool for analyzing. reverse engineering. and extracting firmware images.
        // Reference: https://github.com/ReFirmLabs/binwalk
        $string1_binwalk_greyware_tool_keyword = /binwalk/ nocase ascii wide

    condition:
        any of them
}


rule bitsadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bitsadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bitsadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: bitsadmin suspicious transfer
        // Reference: N/A
        $string1_bitsadmin_greyware_tool_keyword = /bitsadmin\s\/transfer\sdebjob\s\/download\s\/priority\snormal\s\\.{0,1000}\\C\$\\Windows\\.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}


rule bittorent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bittorent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bittorent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]bittorrent.com/fr/
        $string1_bittorent_greyware_tool_keyword = /\\BitTorrent\.exe/ nocase ascii wide

    condition:
        any of them
}


rule bloodhound_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'bloodhound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodhound"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: he neo4j console command is used to start the Neo4j server in console mode. While it is not directly associated with a specific attack technique - it is often used in combination with tools like BloodHound to analyze and visualize data collected from Active Directory environments.
        // Reference: https://github.com/fox-it/BloodHound.py
        $string1_bloodhound_greyware_tool_keyword = /neo4j\sconsole/ nocase ascii wide

    condition:
        any of them
}


rule Browsec_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browsec VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browsec VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Browsec_VPN_greyware_tool_keyword = /omghfjlpggmjjaagoclmmobgdodcjboh/ nocase ascii wide

    condition:
        any of them
}


rule Browser_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browser VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Browser_VPN_greyware_tool_keyword = /jdgilggpfmjpbodmhndmhojklgfdlhob/ nocase ascii wide

    condition:
        any of them
}


rule Browser_C2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Browser-C2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-C2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Post Exploitation agent which uses a browser to do C2 operations.
        // Reference: https://github.com/0x09AL/Browser-C2
        $string1_Browser_C2_greyware_tool_keyword = /http:\/\/127\.0\.0\.1:8081/ nocase ascii wide

    condition:
        any of them
}


rule BullVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'BullVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BullVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_BullVPN_greyware_tool_keyword = /chioafkonnhbpajpengbalkececleldf/ nocase ascii wide

    condition:
        any of them
}


rule cat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: show atftp history
        // Reference: N/A
        $string1_cat_greyware_tool_keyword = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2_cat_greyware_tool_keyword = /cat\s.{0,1000}\.atftp_history/ nocase ascii wide
        // Description: show bash history
        // Reference: N/A
        $string3_cat_greyware_tool_keyword = /cat\s.{0,1000}\.bash_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4_cat_greyware_tool_keyword = /cat\s.{0,1000}\.bash_history/ nocase ascii wide
        // Description: show mysql history
        // Reference: N/A
        $string5_cat_greyware_tool_keyword = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string6_cat_greyware_tool_keyword = /cat\s.{0,1000}\.mysql_history/ nocase ascii wide
        // Description: show nano history
        // Reference: N/A
        $string7_cat_greyware_tool_keyword = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string8_cat_greyware_tool_keyword = /cat\s.{0,1000}\.nano_history/ nocase ascii wide
        // Description: show php history
        // Reference: N/A
        $string9_cat_greyware_tool_keyword = /cat\s.{0,1000}\.php_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10_cat_greyware_tool_keyword = /cat\s.{0,1000}\.php_history/ nocase ascii wide
        // Description: show zsh history
        // Reference: N/A
        $string11_cat_greyware_tool_keyword = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: Enumerating user files history for interesting information
        // Reference: N/A
        $string12_cat_greyware_tool_keyword = /cat\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string13_cat_greyware_tool_keyword = /cat\s.{0,1000}bash\-history/ nocase ascii wide
        // Description: deleting bash history
        // Reference: N/A
        $string14_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\$HISTFILE_cat_greyware_tool_keyword/ nocase ascii wide
        // Description: deleting log files
        // Reference: N/A
        $string15_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\/var\/log\/.{0,1000}\.log/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string16_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s\/var\/log\/auth\.log/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string17_cat_greyware_tool_keyword = /cat\s\/dev\/null\s\>\s~\/\.bash_history/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string18_cat_greyware_tool_keyword = /cat\s\/etc\/passwd/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string19_cat_greyware_tool_keyword = /cat\s\/etc\/shadow/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string20_cat_greyware_tool_keyword = /cat\s\/etc\/sudoers/ nocase ascii wide

    condition:
        any of them
}


rule chattr_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chattr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chattr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: lock out the ability to update the file
        // Reference: N/A
        $string1_chattr_greyware_tool_keyword = /chattr\s\+i\s\$HISTFILE_chattr_greyware_tool_keyword/ nocase ascii wide
        // Description: lock out the ability to update the file
        // Reference: N/A
        $string2_chattr_greyware_tool_keyword = /chattr\s\+i\s.{0,1000}\.bash_history/ nocase ascii wide

    condition:
        any of them
}


rule chcp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chcp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chcp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: chcp displays the number of the active console code page
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1_chcp_greyware_tool_keyword = /cmd\.exe\s\/c\schcp\s\>\&2/ nocase ascii wide

    condition:
        any of them
}


rule chromium_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'chromium' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromium"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string1_chromium_greyware_tool_keyword = /brave.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string2_chromium_greyware_tool_keyword = /brave\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string3_chromium_greyware_tool_keyword = /chrome.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string4_chromium_greyware_tool_keyword = /chrome\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string5_chromium_greyware_tool_keyword = /msedge.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment -  abused by attackers
        // Reference: https://www.splunk.com/en_us/blog/security/mockbin-and-the-art-of-deception-tracing-adversaries-going-headless-and-mocking-apis.html
        $string6_chromium_greyware_tool_keyword = /msedge.{0,1000}\s\-\-headless\s\-\-disable\-gpu\s\-\-remote\-debugging\-port\=/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string7_chromium_greyware_tool_keyword = /msedge\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string8_chromium_greyware_tool_keyword = /opera.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string9_chromium_greyware_tool_keyword = /opera\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide
        // Description: Headless Chromium allows running Chromium in a headless/server environment - downloading a file - abused by attackers
        // Reference: https://redcanary.com/blog/intelligence-insights-june-2023/
        $string10_chromium_greyware_tool_keyword = /vivaldi.{0,1000}\s\-\-headless\s.{0,1000}\s\-\-dump\-dom\shttp/ nocase ascii wide
        // Description: The --load-extension switch allows the source to specify a target directory to load as an extension. This gives malware the opportunity to start a new browser window with their malicious extension loaded.
        // Reference: https://www.mandiant.com/resources/blog/lnk-between-browsers
        $string11_chromium_greyware_tool_keyword = /vivaldi\.exe.{0,1000}\s\-\-load\-extension\=\".{0,1000}\\Users\\.{0,1000}\\Appdata\\Local\\Temp\\/ nocase ascii wide

    condition:
        any of them
}


rule CIMplant_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CIMplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CIMplant"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string1_CIMplant_greyware_tool_keyword = /\%SystemRoot\%\\\\MEMORY\.DMP/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string2_CIMplant_greyware_tool_keyword = /C:\\Windows\\MEMORY\.DMP/ nocase ascii wide

    condition:
        any of them
}


rule Cloud_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Cloud VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cloud VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Cloud_VPN_greyware_tool_keyword = /pcienlhnoficegnepejpfiklggkioccm/ nocase ascii wide

    condition:
        any of them
}


rule cloudflared_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cloudflared' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloudflared"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string1_cloudflared_greyware_tool_keyword = /\._tcp\.argotunnel\.com/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string2_cloudflared_greyware_tool_keyword = /\.v2\.argotunnel\.com/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string3_cloudflared_greyware_tool_keyword = /\/cloudflared\.git/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string4_cloudflared_greyware_tool_keyword = /\/cloudflared\/tunnel\// nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string5_cloudflared_greyware_tool_keyword = /\/cloudflared\-linux\-.{0,1000}\.deb/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string6_cloudflared_greyware_tool_keyword = /\/cloudflared\-linux\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string7_cloudflared_greyware_tool_keyword = /\/usr\/local\/bin\/cloudflared\stunnel/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string8_cloudflared_greyware_tool_keyword = /\\cloudflared\.exe/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string9_cloudflared_greyware_tool_keyword = /\\cloudflared\\cmd\\/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string10_cloudflared_greyware_tool_keyword = /\\cloudflared\-2023\./ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string11_cloudflared_greyware_tool_keyword = /\\cloudflared\-2024\./ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string12_cloudflared_greyware_tool_keyword = /07b95428cfb9cb49c2447c2ff9fbc503225d5de7ff70c643f45399fc2f08c48c/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string13_cloudflared_greyware_tool_keyword = /0b917a040f43b5b120a3288f76e857203cc52f51c2f78c997d4d0c2da3d0c0c5/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string14_cloudflared_greyware_tool_keyword = /0ec73349570f7d8546b9ddfd6b0b409cd622abc133be641bb2a414a2d2b9a21e/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string15_cloudflared_greyware_tool_keyword = /17fa4fd9db3006f9aa649b0160770ebb9e9b8a599f6fb5afce83a16a7cb41bdd/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string16_cloudflared_greyware_tool_keyword = /1b3e09c31048ec7f2ef06166eb47dcdf0e563ca07b6dcc1318fa6f7db3feb458/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string17_cloudflared_greyware_tool_keyword = /2fb6c04c4f95fb8d158af94c137f90ac820716deaf88d8ebec956254e046cb29/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string18_cloudflared_greyware_tool_keyword = /33c9fa0bbaca1c4af7cf7c6016cda366612f497d08edd017bced7c617baa7fc2/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string19_cloudflared_greyware_tool_keyword = /33e6876bd55c2db13a931cf812feb9cb17c071ab45d3b50c588642b022693cdc/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string20_cloudflared_greyware_tool_keyword = /55c11ee0078d85ed35d7df237458e40b6ad687f46fc78b1886f30c197e1683c1/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string21_cloudflared_greyware_tool_keyword = /561304bd23f13aa9185257fb0f055e8790dc64e8cf95287e2bfc9fec160eecf8/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string22_cloudflared_greyware_tool_keyword = /569b8925a41bd1426fc9f88a4d00aa93da747ed4a5ec1c638678ac62ae1a7114/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string23_cloudflared_greyware_tool_keyword = /5868fed5581f3fb186c94b6be63f8b056c571159edb65cc5dafb84553e888d39/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string24_cloudflared_greyware_tool_keyword = /62700c23ce8560628d8eb07ab2adcf863ad901c9f631bb45ed4b4f801f35b2a5/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string25_cloudflared_greyware_tool_keyword = /6ee5eab9a9aa836ac397746a20afbb671971c6553bf8d6a844ba0a7a8de8447e/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string26_cloudflared_greyware_tool_keyword = /9a6f666b2d691d7c6aadd7b854b26cffd76735e9622f3613577b556fe29eb6a1/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string27_cloudflared_greyware_tool_keyword = /b3d21940a10fdef5e415ad70331ce257c24fe3bcf7722262302e0421791f87e8/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string28_cloudflared_greyware_tool_keyword = /b7e394578b41e9a71857e59d04b7bf582e3d0d15f314ab69f269be474a4b9e1a/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string29_cloudflared_greyware_tool_keyword = /ca6ac5c1c1f30675eecf91fe295d703007a754c1b320609ede7aa4783d899e9e/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string30_cloudflared_greyware_tool_keyword = /\-\-chown\=nonroot\s\/go\/src\/github\.com\/cloudflare\/cloudflared\/cloudflared\s\/usr\/local\/bin\// nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string31_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\s\-\-config\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string32_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\screate\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string33_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\sinfo\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string34_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\slist/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string35_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\slogin/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string36_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\sroute\sdns\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string37_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\sroute\sip\sadd\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string38_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\sroute\sip\sshow/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string39_cloudflared_greyware_tool_keyword = /cloudflared\stunnel\srun\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string40_cloudflared_greyware_tool_keyword = /cloudflared\-amd64\.pkg/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string41_cloudflared_greyware_tool_keyword = /cloudflared\-windows\-386\.exe/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string42_cloudflared_greyware_tool_keyword = /cloudflared\-windows\-amd64\.exe/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string43_cloudflared_greyware_tool_keyword = /cloudflared\-windows\-amd64\.msi/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string44_cloudflared_greyware_tool_keyword = /d6c358a2b66fae4f2c9fa4ffa8cd37f6ab9b7d27c83414f70c1d6a210812f0fa/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string45_cloudflared_greyware_tool_keyword = /d79111ec8fa3659c887dd4e82f8ce6ff39391de6860ca0c2045469d6ab76a44f/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string46_cloudflared_greyware_tool_keyword = /dc76f7c6b506d3ec4a92d9a0cda9678c3cb58a9096587dde15897709c7b23a33/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string47_cloudflared_greyware_tool_keyword = /e8118e74c74a62a1d8dc291cb626f46d0056b1284726c2a5d671e20a5e92270c/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string48_cloudflared_greyware_tool_keyword = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string49_cloudflared_greyware_tool_keyword = /echo\s\'alias\sfind\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\>\>\s\"\$user_cloudflared_greyware_tool_keyword\/\.bashrc\"/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string50_cloudflared_greyware_tool_keyword = /ed4f5607dbc3fec5d43fbc22fb12a79d8bca07aa60c8733db7f495b7210d631f/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string51_cloudflared_greyware_tool_keyword = /fffec1382a3f65ecb8f1ebb2c74e3d7aa57485fb4cff4014aadc10b8e9f3abc8/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string52_cloudflared_greyware_tool_keyword = /protocol\-v2\.argotunnel\.com/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string53_cloudflared_greyware_tool_keyword = /sc\screate\sCloudflared\sbinPath\=\\/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string54_cloudflared_greyware_tool_keyword = /sc\.exe\screate\sCloudflared\sbinPath\=\\/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string55_cloudflared_greyware_tool_keyword = /sudo\ssystemctl\sedit\s\-\-full\scloudflared\.service/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string56_cloudflared_greyware_tool_keyword = /test\-cloudflare\-tunnel\-cert\-json\.pem/ nocase ascii wide
        // Description: cloudfared Contains the command-line client for Cloudflare Tunnel - a tunneling daemon that proxies traffic from the Cloudflare network to your origins
        // Reference: https://github.com/cloudflare/cloudflared
        $string57_cloudflared_greyware_tool_keyword = /update\.argotunnel\.com/ nocase ascii wide

    condition:
        any of them
}


rule cobaltstrike_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cobaltstrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cobaltstrike"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: If cobaltstrike uses execute-assembly there is a chance that a file will be created in the UsageLogs logs
        // Reference: https://bohops.com/2021/03/16/investigating-net-clr-usage-log-tampering-techniques-for-edr-evasion/
        $string1_cobaltstrike_greyware_tool_keyword = /\\AppData\\Local\\Microsoft\\CLR_.{0,1000}\\UsageLogs\\.{0,1000}\.exe\.log/ nocase ascii wide

    condition:
        any of them
}


rule Compress_Archive_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Compress-Archive' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Compress-Archive"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string1_Compress_Archive_greyware_tool_keyword = /:\\programdata\\cloud\.exe/ nocase ascii wide
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string2_Compress_Archive_greyware_tool_keyword = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath\s\$env_Compress_Archive_greyware_tool_keyword:TEMP/ nocase ascii wide
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string3_Compress_Archive_greyware_tool_keyword = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath.{0,1000}:\\Windows\\Temp\\/ nocase ascii wide
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4_Compress_Archive_greyware_tool_keyword = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath.{0,1000}\\AppData\\Local\\Temp\\\'/ nocase ascii wide

    condition:
        any of them
}


rule conhost_exe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'conhost.exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "conhost.exe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: conhost in headless mode - no visible window will pop up on the victim machine
        // Reference: https://x.com/TheDFIRReport/status/1721521617908473907?s=20
        $string1_conhost_exe_greyware_tool_keyword = /conhost\.exe\s.{0,1000}\s\-\-headless/ nocase ascii wide

    condition:
        any of them
}


rule copy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'copy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "copy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: copying an executable to a remote machine in the c:\windows directory
        // Reference: https://x.com/ACEResponder/status/1720906842631549377
        $string1_copy_greyware_tool_keyword = /copy\s.{0,1000}\.exe\s\\\\.{0,1000}\\c\$\\Windows\\.{0,1000}\.exe/ nocase ascii wide
        // Description: the actor creating a Shadow Copy and then extracting a copy of the ntds.dit file from it.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2_copy_greyware_tool_keyword = /copy\s.{0,1000}\\NTDS\\ntds\.dit\s.{0,1000}\\Temp\\.{0,1000}\./ nocase ascii wide
        // Description: copy the NTDS.dit file from a Volume Shadow Copy which contains sensitive Active Directory data including password hashes for all domain users
        // Reference: N/A
        $string3_copy_greyware_tool_keyword = /copy\s.{0,1000}NTDS\\NTDS\.dit.{0,1000}Temp/ nocase ascii wide

    condition:
        any of them
}


rule cp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1_cp_greyware_tool_keyword = /cp\s\/etc\/passwd/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string2_cp_greyware_tool_keyword = /cp\s\/etc\/shadow/ nocase ascii wide

    condition:
        any of them
}


rule crond_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crond' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crond"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Masquerading as Linux Crond Process.Masquerading occurs when the name or location of an executable* legitimate or malicious. is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/lnx_auditd_masquerading_crond.yml
        $string1_crond_greyware_tool_keyword = /cp\s\-i\s\/bin\/sh\s.{0,1000}\/crond/ nocase ascii wide

    condition:
        any of them
}


rule crontab_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'crontab' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crontab"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1_crontab_greyware_tool_keyword = /crontab.{0,1000}\ssleep\s.{0,1000}ncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}crontab/ nocase ascii wide

    condition:
        any of them
}


rule cut_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cut' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cut"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1_cut_greyware_tool_keyword = /cut\s\-d:\s\-f1\s\/etc\/passwd/ nocase ascii wide

    condition:
        any of them
}


rule CyberGhost_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'CyberGhost VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CyberGhost VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_CyberGhost_VPN_greyware_tool_keyword = /ffbkglfijbcbgblgflchnbphjdllaogb/ nocase ascii wide

    condition:
        any of them
}


rule cytool_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cytool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cytool"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Disables event collection
        // Reference: N/A
        $string1_cytool_greyware_tool_keyword = /cytool\.exe\sevent_collection\sdisable/ nocase ascii wide
        // Description: Disables protection on Cortex XDR files processes registry and services
        // Reference: N/A
        $string2_cytool_greyware_tool_keyword = /cytool\.exe\sprotect\sdisable/ nocase ascii wide
        // Description: Disables Cortex XDR (Even with tamper protection enabled)
        // Reference: N/A
        $string3_cytool_greyware_tool_keyword = /cytool\.exe\sruntime\sdisable/ nocase ascii wide
        // Description: Disables the cortex agent on startup
        // Reference: N/A
        $string4_cytool_greyware_tool_keyword = /cytool\.exe\sstartup\sdisable/ nocase ascii wide

    condition:
        any of them
}


rule Daily_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Daily VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Daily VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Daily_VPN_greyware_tool_keyword = /namfblliamklmeodpcelkokjbffgmeoo/ nocase ascii wide

    condition:
        any of them
}


rule DBC2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DBC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DBC2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string1_DBC2_greyware_tool_keyword = /https:\/\/api\.dropboxapi\.com\// nocase ascii wide

    condition:
        any of them
}


rule dd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects overwriting (effectively wiping/deleting) the file
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string1_dd_greyware_tool_keyword = /dd\sif\=\/dev\/nul/ nocase ascii wide
        // Description: Detects overwriting (effectively wiping/deleting) the file
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string2_dd_greyware_tool_keyword = /dd\sif\=\/dev\/zero/ nocase ascii wide

    condition:
        any of them
}


rule debugdfs_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'debugdfs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "debugdfs"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Linux SIEM Bypass with debugdfs shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string1_debugdfs_greyware_tool_keyword = /debugfs\s\/dev\// nocase ascii wide

    condition:
        any of them
}


rule DEEPRISM_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DEEPRISM VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DEEPRISM VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_DEEPRISM_VPN_greyware_tool_keyword = /bihhflimonbpcfagfadcnbbdngpopnjb/ nocase ascii wide

    condition:
        any of them
}


rule dev_tunnels_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dev-tunnels' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dev-tunnels"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string1_dev_tunnels_greyware_tool_keyword = /\shost\s\-p\s.{0,1000}\s\-\-allow\-anonymous\s\-\-protocol\shttps/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string2_dev_tunnels_greyware_tool_keyword = /\.asse\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string3_dev_tunnels_greyware_tool_keyword = /\.exe\shost\s\-p\s.{0,1000}\s\-\sallow\-anonymous/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string4_dev_tunnels_greyware_tool_keyword = /\.exe\sport\screate\s\-p\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string5_dev_tunnels_greyware_tool_keyword = /\-443\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string6_dev_tunnels_greyware_tool_keyword = /asse\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string7_dev_tunnels_greyware_tool_keyword = /auc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string8_dev_tunnels_greyware_tool_keyword = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string9_dev_tunnels_greyware_tool_keyword = /brs\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string10_dev_tunnels_greyware_tool_keyword = /devtunnel\screate\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string11_dev_tunnels_greyware_tool_keyword = /devtunnel\shost\s\-p\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string12_dev_tunnels_greyware_tool_keyword = /devtunnel.{0,1000}\suser\slogin\s\-/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string13_dev_tunnels_greyware_tool_keyword = /devtunnel\.exe\s/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string14_dev_tunnels_greyware_tool_keyword = /eun1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string15_dev_tunnels_greyware_tool_keyword = /euw\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string16_dev_tunnels_greyware_tool_keyword = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string17_dev_tunnels_greyware_tool_keyword = /https:\/\/.{0,1000}\..{0,1000}\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string18_dev_tunnels_greyware_tool_keyword = /https:\/\/.{0,1000}\.brs\.devtunnels\.ms\// nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string19_dev_tunnels_greyware_tool_keyword = /https:\/\/.{0,1000}\.euw\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string20_dev_tunnels_greyware_tool_keyword = /https:\/\/.{0,1000}\.use\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string21_dev_tunnels_greyware_tool_keyword = /https:\/\/aka\.ms\/DevTunnelCliInstall/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string22_dev_tunnels_greyware_tool_keyword = /inc1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string23_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Connections\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string24_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Contracts\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string25_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Management\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string26_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Ssh\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string27_dev_tunnels_greyware_tool_keyword = /Microsoft\.DevTunnels\.Ssh\.Tcp\.dll/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string28_dev_tunnels_greyware_tool_keyword = /ssh\s\@ssh\..{0,1000}\.devtunnels\.ms/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string29_dev_tunnels_greyware_tool_keyword = /tunnels\-prod\-rel\-tm\.trafficmanager\.net/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string30_dev_tunnels_greyware_tool_keyword = /uks1\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string31_dev_tunnels_greyware_tool_keyword = /use\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string32_dev_tunnels_greyware_tool_keyword = /use2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string33_dev_tunnels_greyware_tool_keyword = /usw2\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string34_dev_tunnels_greyware_tool_keyword = /usw3\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Dev tunnels allow developers to securely share local web services across the internet. Enabling you to connect your local development environment with cloud services and share work in progress with colleagues or aid in building webhooks
        // Reference: https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview
        $string35_dev_tunnels_greyware_tool_keyword = /wss:\/\/.{0,1000}\.tunnels\.api\.visualstudio\.com\/api\/v1\/Connect\// nocase ascii wide

    condition:
        any of them
}


rule dig_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dig
        // Reference: https://linux.die.net/man/1/dig
        $string1_dig_greyware_tool_keyword = /dig\s.{0,1000}\saxfr\s.{0,1000}\@/ nocase ascii wide
        // Description: classic DNS Zone transfer request. The idea behind it is to attempt to duplicate all the DNS records for a given zone (or domain). This is a technique often used by attackers to gather information about the infrastructure of a target organization.
        // Reference: https://linux.die.net/man/1/dig
        $string2_dig_greyware_tool_keyword = /dig\s.{0,1000}\@.{0,1000}\saxfr/ nocase ascii wide

    condition:
        any of them
}


rule dir_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dir"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: threat actors searched for Active Directory related DLLs in directories
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1_dir_greyware_tool_keyword = /\sdir\s\/s\s.{0,1000}\/\sMicrosoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide

    condition:
        any of them
}


rule diskshadow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'diskshadow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "diskshadow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: List shadow copies using diskshadow
        // Reference: N/A
        $string1_diskshadow_greyware_tool_keyword = /diskshadow\slist\sshadows\sall/ nocase ascii wide

    condition:
        any of them
}


rule dns_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dns' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
        $string1_dns_greyware_tool_keyword = /\sdenied\sAXFR\sfrom\s/ nocase ascii wide
        // Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
        $string2_dns_greyware_tool_keyword = /\sdropping\ssource\sport\szero\spacket\sfrom\s/ nocase ascii wide
        // Description: Detects suspicious DNS error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/named_rules.xml
        $string3_dns_greyware_tool_keyword = /\sexiting\s\(due\sto\sfatal\serror\)/ nocase ascii wide

    condition:
        any of them
}


rule dnscmd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dnscmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscmd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: the actor gather information about the target environment
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1_dnscmd_greyware_tool_keyword = /dnscmd\s\.\s\/enumrecords\s\/zone\s/ nocase ascii wide
        // Description: the actor gather information about the target environment
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string2_dnscmd_greyware_tool_keyword = /dnscmd\s\.\s\/enumzones/ nocase ascii wide

    condition:
        any of them
}


rule DotVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DotVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DotVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_DotVPN_greyware_tool_keyword = /kpiecbcckbofpmkkkdibbllpinceiihk/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string2_DotVPN_greyware_tool_keyword = /mjolnodfokkkaichkcjipfgblbfgojpa/ nocase ascii wide

    condition:
        any of them
}


rule dpapi_py_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dpapi.py' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dpapi.py"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: the command is used to extract the Data Protection API (DPAPI) backup keys from a target system. DPAPI is a Windows API that provides data protection services to secure sensitive data. such as private keys. passwords. and other secrets. By obtaining the DPAPI backup keys. an attacker can potentially decrypt sensitive data stored on the target system or impersonate users. gaining unauthorized access to other systems and resources.
        // Reference: N/A
        $string1_dpapi_py_greyware_tool_keyword = /dpapi\.py\sbackupkeys\s\-t\s.{0,1000}\/.{0,1000}\@/ nocase ascii wide

    condition:
        any of them
}


rule dsquery_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'dsquery' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dsquery"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate domain trusts with dsquery
        // Reference: N/A
        $string1_dsquery_greyware_tool_keyword = /dsquery\s.{0,1000}\s\-filter\s.{0,1000}\(objectClass\=trustedDomain\).{0,1000}\s\-attr\s/ nocase ascii wide
        // Description: Finding users Not Required to Have a Password
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string2_dsquery_greyware_tool_keyword = /\-filter\s.{0,1000}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:\=32/ nocase ascii wide
        // Description: Finding accounts with Kerberos Pre-Authentication Disabled
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string3_dsquery_greyware_tool_keyword = /\-filter\s.{0,1000}\(\&\(objectCategory\=person\)\(objectClass\=user\)\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:\=4194304/ nocase ascii wide
        // Description: Finding accounts with constrained delegation
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string4_dsquery_greyware_tool_keyword = /\-filter\s.{0,1000}\(\&\(objectClass\=User\)\(msDS\-AllowedToDelegateTo\=/ nocase ascii wide
        // Description: Finding Kerberoastable Users
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string5_dsquery_greyware_tool_keyword = /\-filter\s.{0,1000}\(\&\(objectClass\=user\)\(servicePrincipalName\=.{0,1000}\)\(\!\(cn\=krbtgt\)\)\(\!\(samaccounttype\=805306369/ nocase ascii wide
        // Description: Finding accounts with SPNs
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string6_dsquery_greyware_tool_keyword = /\-filter\s.{0,1000}\(\&\(objectClass\=User\)\(serviceprincipalname\=.{0,1000}\)\(samaccountname\=.{0,1000}\s\-limit\s0\s\-attr\ssamaccountname\sserviceprincipalname/ nocase ascii wide
        // Description: Finding accounts with unconstrained delegation
        // Reference: https://www.politoinc.com/post/ldap-queries-for-offensive-and-defensive-operations
        $string7_dsquery_greyware_tool_keyword = /\-filter\s.{0,1000}\(userAccountControl:1\.2\.840\.113556\.1\.4\.803:\=524288\)/ nocase ascii wide

    condition:
        any of them
}


rule ducktail_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ducktail' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ducktail"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: infostealer command to retrieve public ip address
        // Reference: https://www.trendmicro.com/en_be/research/23/e/managed-xdr-investigation-of-ducktail-in-trend-micro-vision-one.html
        $string1_ducktail_greyware_tool_keyword = /\-\-headless\s\-\-disable\-gpu\s\-\-disable\-logging\s\-\-dump\-dom\shttps:\/\/getip\.pro/ nocase ascii wide

    condition:
        any of them
}


rule Earth_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Earth VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Earth VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Earth_VPN_greyware_tool_keyword = /nabbmpekekjknlbkgpodfndbodhijjem/ nocase ascii wide

    condition:
        any of them
}


rule echo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'echo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "echo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string1_echo_greyware_tool_keyword = /\%COMSPEC\%.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string2_echo_greyware_tool_keyword = /cmd.{0,1000}echo.{0,1000}\\pipe\\/ nocase ascii wide
        // Description: Adversaries may attempt to test echo command after exploitation
        // Reference: N/A
        $string3_echo_greyware_tool_keyword = /cmd\.exe\s\s\/S\s\/D\s\/c.{0,1000}\secho\s123/ nocase ascii wide
        // Description: alternative to whoami
        // Reference: N/A
        $string4_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s\%username\%/ nocase ascii wide
        // Description: Named pipe impersonation
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string5_echo_greyware_tool_keyword = /cmd\.exe\s\/c\secho\s.{0,1000}\s\>\s\\\\\.\\pipe\\/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string6_echo_greyware_tool_keyword = /echo\s\'\'\s\>\s~\/\.bash_history/ nocase ascii wide
        // Description: This command disables kprobes by writing '0' to the enabled file. Kprobes are dynamic breakpoints in the Linux kernel that can be used to intercept functions and gather information for debugging or monitoring.
        // Reference: N/A
        $string7_echo_greyware_tool_keyword = /echo\s0\s\>\s\/sys\/kernel\/debug\/kprobes\/enabled/ nocase ascii wide
        // Description: This command turns off tracing for a specific instance
        // Reference: N/A
        $string8_echo_greyware_tool_keyword = /echo\s0\s\>\s\/sys\/kernel\/debug\/tracing\/instances\/\$.{0,1000}\/tracing_on/ nocase ascii wide
        // Description: linux command abused by attacker
        // Reference: N/A
        $string9_echo_greyware_tool_keyword = /echo\s\'set\s\+o\shistory\'\s\>\>\s\/etc\/profile/ nocase ascii wide

    condition:
        any of them
}


rule elastic_agent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'elastic-agent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elastic-agent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: uninstall elast-agent from the system
        // Reference: N/A
        $string1_elastic_agent_greyware_tool_keyword = /elastic\-agent\.exe\suninstall/ nocase ascii wide

    condition:
        any of them
}


rule email_format_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'email-format' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "email-format"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attackers to find informations about a company users
        // Reference: https://www.email-format.com
        $string1_email_format_greyware_tool_keyword = /https:\/\/www\.email\-format\.com\/d\// nocase ascii wide

    condition:
        any of them
}


rule evilrdp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'evilrdp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilrdp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string1_evilrdp_greyware_tool_keyword = /dorgreen1\@gmail\.com/ nocase ascii wide
        // Description: Th evil twin of aardwolfgui using the aardwolf RDP client library that gives you extended control over the target and additional scripting capabilities from the command line.
        // Reference: https://github.com/skelsec/evilrdp
        $string2_evilrdp_greyware_tool_keyword = /info\@skelsecprojects\.com/ nocase ascii wide

    condition:
        any of them
}


rule Excel_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Excel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Excel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: prevent any warnings or alerts when Python functions are about to be executed. Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet
        // Reference: https://github.com/tsale/Sigma_rules/blob/main/MISC/pythonfunctionwarnings_disabled.yml
        $string1_Excel_greyware_tool_keyword = /reg\sadd\sHKCU\\software\\policies\\microsoft\\office\\16\.0\\excel\\security\s\/v\sPythonFunctionWarnings\s\/t\sREG_DWORD\s\/d\s0\s\/f\?/ nocase ascii wide
        // Description: prevent any warnings or alerts when Python functions are about to be executed. Threat actors could run malicious code through the new Microsoft Excel feature that allows Python to run within the spreadsheet
        // Reference: https://github.com/tsale/Sigma_rules/blob/main/MISC/pythonfunctionwarnings_disabled.yml
        $string2_Excel_greyware_tool_keyword = /Set\-ItemProperty\s.{0,1000}\\excel\\security.{0,1000}pythonfunctionwarnings.{0,1000}0/ nocase ascii wide

    condition:
        any of them
}


rule exegol_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'exegol' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "exegol"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string1_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.cmdline/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string2_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.dlllist\s\-\-pid\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string3_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.filescan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string4_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.handles\s\-\-pid\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string5_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.info/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string6_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.malfind/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string7_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.netscan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string8_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.netstat/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string9_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.pslist/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string10_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.psscan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string11_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.pstree/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string12_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivelist/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string13_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.hivescan/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string14_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string15_exegol_greyware_tool_keyword = /\s\-f\s.{0,1000}\.dmp\swindows\.registry\.printkey.{0,1000}Software\\Microsoft\\Windows\\CurrentVersion/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string16_exegol_greyware_tool_keyword = /\shttp\-put\-server\.py/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string17_exegol_greyware_tool_keyword = /\/http\-put\-server\.py/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string18_exegol_greyware_tool_keyword = /dig\saxfr\s.{0,1000}\s\@/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string19_exegol_greyware_tool_keyword = /ftp\-server\s\-u\s.{0,1000}\s\-P\s.{0,1000}\s\-p\s2121/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string20_exegol_greyware_tool_keyword = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string21_exegol_greyware_tool_keyword = /net\srpc\sgroup\saddmem\s\'Domain\sadmins\'\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string22_exegol_greyware_tool_keyword = /net\srpc\sgroup\smembers\s\'Domain\sadmins\'\s\-U\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string23_exegol_greyware_tool_keyword = /netdiscover\s\-i\s.{0,1000}\s\-r\s.{0,1000}\/24/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string24_exegol_greyware_tool_keyword = /ngrok\sauthtoken\sAUTHTOKEN:::https:\/\/dashboard\.ngrok\.com\/get\-started\/your\-authtoken/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string25_exegol_greyware_tool_keyword = /nmap\s\-Pn\s\-v\s\-sS\s\-F/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string26_exegol_greyware_tool_keyword = /pwnedornot\.py\s\-d\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string27_exegol_greyware_tool_keyword = /scout\saws\s\-\-profile\sdefault\s\-f/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string28_exegol_greyware_tool_keyword = /scout\sazure\s\-\-cli/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string29_exegol_greyware_tool_keyword = /screen\s\/dev\/ttyACM0\s115200/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string30_exegol_greyware_tool_keyword = /snmpwalk\s\-c\spublic\s\-v\s1\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string31_exegol_greyware_tool_keyword = /snmpwalk\s\-c\spublic\s\-v\s2c\s/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string32_exegol_greyware_tool_keyword = /tailscale\sup\s\-\-advertise\-routes\=.{0,1000}\/24/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string33_exegol_greyware_tool_keyword = /tailscaled\s\-\-tun\=userspace\-networking\s\-\-socks5\-server\=/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string34_exegol_greyware_tool_keyword = /volatility2\s\-\-profile\=/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string35_exegol_greyware_tool_keyword = /volatility3\s\-f\s.{0,1000}\.dmp/ nocase ascii wide
        // Description: Fully featured and community-driven hacking environment with hundreds of offensive tools
        // Reference: https://github.com/ThePorgs/Exegol
        $string36_exegol_greyware_tool_keyword = /vulny\-code\-static\-analysis\s\-\-dir\s/ nocase ascii wide

    condition:
        any of them
}


rule export_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'export' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "export"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string1_export_greyware_tool_keyword = /export\sHISTFILE\=\/dev\/null/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2_export_greyware_tool_keyword = /export\sHISTFILESIZE\=0/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string3_export_greyware_tool_keyword = /export\sHISTSIZE\=0/ nocase ascii wide

    condition:
        any of them
}


rule ExpressVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ExpressVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExpressVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_ExpressVPN_greyware_tool_keyword = /fgddmllnllkalaagkghckoinaemmogpe/ nocase ascii wide

    condition:
        any of them
}


rule FastestVPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FastestVPN Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FastestVPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_FastestVPN_Proxy_greyware_tool_keyword = /jedieiamjmoflcknjdjhpieklepfglin/ nocase ascii wide

    condition:
        any of them
}


rule FastStunnel_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FastStunnel VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FastStunnel VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_FastStunnel_VPN_greyware_tool_keyword = /bblcccknbdbplgmdjnnikffefhdlobhp/ nocase ascii wide

    condition:
        any of them
}


rule fiddler_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'fiddler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fiddler"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string1_fiddler_greyware_tool_keyword = /\/download\/fiddler\/fiddler\-everywhere\-windows/ nocase ascii wide
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string2_fiddler_greyware_tool_keyword = /\/Fiddler\sEverywhere\s.{0,1000}\..{0,1000}\..{0,1000}\.exe/ nocase ascii wide
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string3_fiddler_greyware_tool_keyword = /\\Fiddler\sEverywhere\s.{0,1000}\..{0,1000}\..{0,1000}\.exe/ nocase ascii wide
        // Description: fiddler - capture https requests
        // Reference: https://www.telerik.com/
        $string4_fiddler_greyware_tool_keyword = /https:\/\/www\.telerik\.com\/download\/fiddler\// nocase ascii wide

    condition:
        any of them
}


rule file_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'file.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "file.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_file_io_greyware_tool_keyword = /https:\/\/file\.io\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2_file_io_greyware_tool_keyword = /https:\/\/file\.io\/\?title\=/ nocase ascii wide

    condition:
        any of them
}


rule find_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'find' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "find"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: truncate every file under /var/log to size 0 - no log content = no forensic.
        // Reference: N/A
        $string1_find_greyware_tool_keyword = /\/\?\?\?\/\?\?\?\/f\?n\?\s\/var\/log\s\-type\sf\s\-exec\s\/\?\?\?\/\?\?\?\/tr\?\?\?\?\?e\s\-s\s0\s{}\s\\/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string2_find_greyware_tool_keyword = /dir\s\/a\sC:\\pagefile\.sys\s\|\sfindstr\s\/R\s/ nocase ascii wide
        // Description: It can be used to break out from restricted environments by spawning an interactive system shell.
        // Reference: N/A
        $string3_find_greyware_tool_keyword = /find\s\.\s\-exec\s\/bin\/sh\s\\\;\s\-quit/ nocase ascii wide
        // Description: Find sensitive files
        // Reference: N/A
        $string4_find_greyware_tool_keyword = /find\s\/\s\-name\sauthorized_keys\s.{0,1000}\>\s\/dev\/null/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string5_find_greyware_tool_keyword = /find\s\/\s\-name\sid_dsa\s2\>/ nocase ascii wide
        // Description: Find sensitive files
        // Reference: N/A
        $string6_find_greyware_tool_keyword = /find\s\/\s\-name\sid_rsa\s.{0,1000}\>\s\/dev\/null/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string7_find_greyware_tool_keyword = /find\s\/\s\-name\sid_rsa\s2\>/ nocase ascii wide
        // Description: Find SGID enabled files
        // Reference: N/A
        $string8_find_greyware_tool_keyword = /find\s\/\s\-perm\s\/2000\s\-ls\s2\>\/dev\/null/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string9_find_greyware_tool_keyword = /find\s\/\s\-perm\s\+4000\s\-type\sf\s2\>\/dev\/null/ nocase ascii wide
        // Description: Find SGID enabled files
        // Reference: N/A
        $string10_find_greyware_tool_keyword = /find\s\/\s\-perm\s\+8000\s\-ls\s2\>\/dev\/null/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.# sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string11_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-2000/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.# sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string12_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-4000/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string13_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-4000\s\-type\sf\s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string14_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-g\=s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. sticky bits
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string15_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-u\=s/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string16_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s2\>\/dev\/null/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string17_find_greyware_tool_keyword = /find\s\/\s\-perm\s\-u\=s\s\-type\sf\s\-group\s.{0,1000}\/dev\/null/ nocase ascii wide
        // Description: Find SUID enabled files
        // Reference: N/A
        $string18_find_greyware_tool_keyword = /find\s\/\s\-uid\s0\s\-perm\s\-4000\s\-type\sf\s/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string19_find_greyware_tool_keyword = /find\s\/\s\-user\sroot\s\-perm\s\-6000\s\-type\sf\s2\>/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string20_find_greyware_tool_keyword = /find\s\/.{0,1000}\s\-perm\s\-04000\s\-o\s\-perm\s\-02000/ nocase ascii wide
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string21_find_greyware_tool_keyword = /find\s\/.{0,1000}\s\-perm\s\-u\=s\s\-type\sf\s2\>/ nocase ascii wide
        // Description: truncate every file under /var/log to size 0 - no log content = no forensic.
        // Reference: N/A
        $string22_find_greyware_tool_keyword = /find\s\/var\/log\s\-type\sf\s\-exec\struncate\s\-s\s0\s{}\s\\/ nocase ascii wide

    condition:
        any of them
}


rule findstr_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'findstr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - gpp finder
        // Reference: N/A
        $string1_findstr_greyware_tool_keyword = /findstr\s.{0,1000}cpassword\s.{0,1000}\\sysvol\\.{0,1000}\.xml/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2_findstr_greyware_tool_keyword = /findstr\s.{0,1000}vnc\.ini/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string3_findstr_greyware_tool_keyword = /findstr\s\/si\ssecret\s.{0,1000}\.docx/ nocase ascii wide

    condition:
        any of them
}


rule Fornex_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Fornex VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Fornex VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Fornex_VPN_greyware_tool_keyword = /egblhcjfjmbjajhjhpmnlekffgaemgfh/ nocase ascii wide

    condition:
        any of them
}


rule FoxyProxy_Standard_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FoxyProxy Standard' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FoxyProxy Standard"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_FoxyProxy_Standard_greyware_tool_keyword = /gcknhkkoolaabfmlnjonogaaifnjlfnp/ nocase ascii wide

    condition:
        any of them
}


rule Free_Avira_Phantom_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Avira Phantom VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Avira Phantom VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_Avira_Phantom_VPN_greyware_tool_keyword = /dfkdflfgjdajbhocmfjolpjbebdkcjog/ nocase ascii wide

    condition:
        any of them
}


rule Free_Fast_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Fast VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Fast VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_Fast_VPN_greyware_tool_keyword = /macdlemfnignjhclfcfichcdhiomgjjb/ nocase ascii wide

    condition:
        any of them
}


rule Free_One_Touch_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free One Touch VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free One Touch VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_One_Touch_VPN_greyware_tool_keyword = /inligpkjkhbpifecbdjhmdpcfhnlelja/ nocase ascii wide

    condition:
        any of them
}


rule Free_Proxy_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Proxy VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Proxy VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_Proxy_VPN_greyware_tool_keyword = /dhadilbmmjiooceioladdphemaliiobo/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string2_Free_Proxy_VPN_greyware_tool_keyword = /pgfpignfckbloagkfnamnolkeaecfgfh/ nocase ascii wide

    condition:
        any of them
}


rule Free_Residential_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free Residential VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free Residential VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_Residential_VPN_greyware_tool_keyword = /jpgljfpmoofbmlieejglhonfofmahini/ nocase ascii wide

    condition:
        any of them
}


rule FREE_VPN_DEWELOPMENT_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FREE VPN DEWELOPMENT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FREE VPN DEWELOPMENT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_FREE_VPN_DEWELOPMENT_greyware_tool_keyword = /ifnaibldjfdmaipaddffmgcmekjhiloa/ nocase ascii wide

    condition:
        any of them
}


rule Free_VPN_for_Chrome_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free VPN for Chrome' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free VPN for Chrome"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_VPN_for_Chrome_greyware_tool_keyword = /klnkiajpmpkkkgpgbogmcgfjhdoljacg/ nocase ascii wide

    condition:
        any of them
}


rule Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Free VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Free_VPN_greyware_tool_keyword = /jgbaghohigdbgbolncodkdlpenhcmcge/ nocase ascii wide
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string2_Free_VPN_greyware_tool_keyword = /majdfhpaihoncoakbjgbdhglocklcgno/ nocase ascii wide

    condition:
        any of them
}


rule freefilesync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'freefilesync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "freefilesync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string1_freefilesync_greyware_tool_keyword = /\/FreeFileSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string2_freefilesync_greyware_tool_keyword = /\/FreeFileSync_.{0,1000}_Windows_Setup\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string3_freefilesync_greyware_tool_keyword = /\/FreeFileSyncPortable_.{0,1000}\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string4_freefilesync_greyware_tool_keyword = /\/RealTimeSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string5_freefilesync_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\FreeFileSync_is1/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string6_freefilesync_greyware_tool_keyword = /\\FreeFileSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string7_freefilesync_greyware_tool_keyword = /\\FreeFileSync\\Logs\\/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string8_freefilesync_greyware_tool_keyword = /\\FreeFileSync_.{0,1000}_Windows_Setup\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string9_freefilesync_greyware_tool_keyword = /\\FreeFileSyncPortable_.{0,1000}\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string10_freefilesync_greyware_tool_keyword = /\\Program\sFiles\\FreeFileSync/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string11_freefilesync_greyware_tool_keyword = /\\RealTimeSync\.exe/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string12_freefilesync_greyware_tool_keyword = /\-Command\sAdd\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Program\sFiles\\FreeFileSync\\Bin\\/ nocase ascii wide
        // Description: freefilesync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://freefilesync.org/download.php
        $string13_freefilesync_greyware_tool_keyword = /SOFTWARE\\WOW6432Node\\FreeFileSync/ nocase ascii wide

    condition:
        any of them
}


rule frp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'frp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string1_frp_greyware_tool_keyword = /\/frp\.git/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string2_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string3_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string4_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string5_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string6_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string7_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string8_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string9_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string10_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string11_frp_greyware_tool_keyword = /\/frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string12_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string13_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string14_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string15_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string16_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string17_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string18_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string19_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string20_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string21_frp_greyware_tool_keyword = /\\frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string22_frp_greyware_tool_keyword = /fatedier\/frp/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string23_frp_greyware_tool_keyword = /frpc\s\-c\s.{0,1000}frpc\.ini/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string24_frp_greyware_tool_keyword = /frpc\sreload\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string25_frp_greyware_tool_keyword = /frpc\sstatus\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string26_frp_greyware_tool_keyword = /frpc\sverify\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string27_frp_greyware_tool_keyword = /frpc_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string28_frp_greyware_tool_keyword = /frpc_windows_arm64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string29_frp_greyware_tool_keyword = /frps\s\-c\s.{0,1000}frps\.toml/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string30_frp_greyware_tool_keyword = /frps_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string31_frp_greyware_tool_keyword = /frps_windows_arm64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string32_frp_greyware_tool_keyword = /ssh\s\-o\s\'proxycommand\ssocat\s\-\s/ nocase ascii wide

    condition:
        any of them
}


rule ftype_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ftype' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ftype"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: will return the file type information for file types that include the string dfil - hidden objectif is to find cmdfile string
        // Reference: N/A
        $string1_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\s.{0,1000}dfil/ nocase ascii wide
        // Description: will return the file type information for file types that include the string SHCm - hidden objectif is to find SHCmdFile string
        // Reference: N/A
        $string2_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\s.{0,1000}SHCm/ nocase ascii wide
        // Description: will return the file type information for file types that include the string dfil - hidden objectif is to find cmdfile string
        // Reference: N/A
        $string3_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\sdfil/ nocase ascii wide
        // Description: will return the file type information for file types that include the string SHCm - hidden objectif is to find SHCmdFile string
        // Reference: N/A
        $string4_ftype_greyware_tool_keyword = /ftype\s.{0,1000}findstr\sSHCm/ nocase ascii wide

    condition:
        any of them
}


rule FudgeC2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'FudgeC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FudgeC2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string1_FudgeC2_greyware_tool_keyword = /http.{0,1000}\/\/127\.0\.0\.1:5001/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string2_FudgeC2_greyware_tool_keyword = /http.{0,1000}\/\/localhost:5001/ nocase ascii wide

    condition:
        any of them
}


rule GeoProxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GeoProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GeoProxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_GeoProxy_greyware_tool_keyword = /pooljnboifbodgifngpppfklhifechoe/ nocase ascii wide

    condition:
        any of them
}


rule Get_WmiObject_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Get-WmiObject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-WmiObject"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get logged on user on remote host with Get-WmiObject
        // Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
        $string1_Get_WmiObject_greyware_tool_keyword = /Get\-WmiObject\s\?ComputerName\s.{0,1000}\s\?Class\sWin32_ComputerSystem\s\|\s.{0,1000}\sUserName/ nocase ascii wide
        // Description: Get SCCM server with Get-WmiObject
        // Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
        $string2_Get_WmiObject_greyware_tool_keyword = /Get\-WmiObject\s\-class\sSMS_Authority\s\-namespace\sroot\\CCM/ nocase ascii wide
        // Description: Get logged on user on remote host with Get-WmiObject
        // Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
        $string3_Get_WmiObject_greyware_tool_keyword = /Get\-WmiObject\swin32_loggedonuser\s\-ComputerName\s/ nocase ascii wide

    condition:
        any of them
}


rule Getcap_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Getcap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Getcap"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Enumerating File Capabilities with Getcap
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_Getcap_greyware_tool_keyword = /getcap\s\-r\s\/\s2\>\/dev\/null/ nocase ascii wide

    condition:
        any of them
}


rule getent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'getent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "getent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1_getent_greyware_tool_keyword = /getent\spasswd\s\|\scut\s\-d:\s\-f1/ nocase ascii wide

    condition:
        any of them
}


rule github_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'github' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "github"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string1_github_greyware_tool_keyword = /\/github\.com.{0,1000}\.exe\?raw\=true/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string2_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/archive\/refs\/tags\/.{0,1000}\.zip/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string3_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string4_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string5_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string6_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string7_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string8_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string9_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bash/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string10_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string11_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string12_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string13_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string14_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string15_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string16_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string17_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string18_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string19_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string20_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string21_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string22_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string23_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string24_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string25_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string26_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string27_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string28_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string29_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string30_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string31_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string32_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string33_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string34_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string35_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string36_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string37_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string38_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string39_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string40_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string41_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string42_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string43_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string44_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string45_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string46_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string47_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string48_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string49_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string50_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string51_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string52_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string53_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string54_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string55_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string56_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string57_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string58_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string59_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string60_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string61_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string62_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string63_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string64_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string65_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string66_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string67_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string68_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string69_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string70_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string71_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string72_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string73_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string74_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string75_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string76_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string77_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string78_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string79_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string80_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string81_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string82_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string83_github_greyware_tool_keyword = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.zip/ nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string84_github_greyware_tool_keyword = /codeload\.github\.com\// nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string85_github_greyware_tool_keyword = /objects\.githubusercontent\.com\/github\-production\-release\-asset\-/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string86_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string87_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string88_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string89_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string90_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string91_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string92_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.bash/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string93_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string94_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string95_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string96_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string97_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string98_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string99_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string100_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string101_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string102_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string103_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string104_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string105_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string106_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string107_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string108_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string109_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string110_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string111_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string112_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string113_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string114_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string115_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string116_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string117_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string118_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string119_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string120_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string121_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string122_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string123_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string124_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string125_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string126_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string127_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string128_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string129_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string130_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string131_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string132_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string133_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string134_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string135_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string136_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string137_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string138_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string139_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string140_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string141_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string142_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string143_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string144_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string145_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string146_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string147_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string148_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string149_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string150_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string151_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string152_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string153_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string154_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string155_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string156_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string157_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string158_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string159_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string160_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string161_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string162_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string163_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string164_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string165_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string166_github_greyware_tool_keyword = /raw\.githubusercontent\.com.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}


rule golang_c2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'golang_c2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "golang_c2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C2 written in Go for red teams aka gorfice2k
        // Reference: https://github.com/m00zh33/golang_c2
        $string1_golang_c2_greyware_tool_keyword = /http:\/\/127\.0\.0\.1:8000\/gate\.html/ nocase ascii wide

    condition:
        any of them
}


rule Gom_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Gom VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Gom VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Gom_VPN_greyware_tool_keyword = /ckiahbcmlmkpfiijecbpflfahoimklke/ nocase ascii wide

    condition:
        any of them
}


rule goMatrixC2_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'goMatrixC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goMatrixC2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string1_goMatrixC2_greyware_tool_keyword = /https:\/\/matrix\.org\/_matrix\/client\/r0\/rooms\/.{0,1000}\/send\/m\.room\.message/ nocase ascii wide

    condition:
        any of them
}


rule Goodsync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Goodsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Goodsync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string1_Goodsync_greyware_tool_keyword = /\/GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string2_Goodsync_greyware_tool_keyword = /\\GoodSync\-2.{0,1000}\-.{0,1000}\.log/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string3_Goodsync_greyware_tool_keyword = /\\GoodSync\-vsub\-Setup\.exe/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string4_Goodsync_greyware_tool_keyword = /\\Siber\sSystems\\GoodSync\\/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string5_Goodsync_greyware_tool_keyword = /\\Users\\.{0,1000}\\AppData\\Local\\GoodSync/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string6_Goodsync_greyware_tool_keyword = /Copy\sNew\s.{0,1000}gdrive:\/\/www\.googleapis\.com\/GS_Sync\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string7_Goodsync_greyware_tool_keyword = /Copy\sNew\s.{0,1000}sftp:\/\// nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string8_Goodsync_greyware_tool_keyword = /GoodSync\sServer/ nocase ascii wide
        // Description: GoodSync is a backup and file synchronization program abused by attacker for data exfiltration
        // Reference: https://www.goodsync.com/
        $string9_Goodsync_greyware_tool_keyword = /GoodSync\-vsub\-2Go\-Setup\.exe/ nocase ascii wide

    condition:
        any of them
}


rule googleweblight_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'googleweblight.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "googleweblight.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Open Redirect vulnerability being exploited by threat actors in Google Web Light
        // Reference: https://x.com/1ZRR4H/status/1723062039680000255
        $string1_googleweblight_com_greyware_tool_keyword = /https:\/\/googleweblight\.com\/i\?u\=.{0,1000}ipfs\..{0,1000}\.html/ nocase ascii wide

    condition:
        any of them
}


rule GoToMyPC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'GoToMyPC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoToMyPC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string1_GoToMyPC_greyware_tool_keyword = /\sDownloadServer\=https:\/\/www\.gotomypc\.com\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string2_GoToMyPC_greyware_tool_keyword = /\sgotoopener:\/\/launch\.getgo\.com\// nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string3_GoToMyPC_greyware_tool_keyword = /\sLoggingServer\=logging\.getgo\.com\sProxyHost\=/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string4_GoToMyPC_greyware_tool_keyword = /\\AppData\\Local\\GoToMyPC\\/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string5_GoToMyPC_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\gosetup\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string6_GoToMyPC_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}\\GoToOpener\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string7_GoToMyPC_greyware_tool_keyword = /\\Citrix\\GoToMyPc\\FileTransfer\\history/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string8_GoToMyPC_greyware_tool_keyword = /\\Citrix\\GoToMyPc\\GuestInvite/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string9_GoToMyPC_greyware_tool_keyword = /\\g2comm\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string10_GoToMyPC_greyware_tool_keyword = /\\g2fileh\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string11_GoToMyPC_greyware_tool_keyword = /\\g2host\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string12_GoToMyPC_greyware_tool_keyword = /\\g2mainh\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string13_GoToMyPC_greyware_tool_keyword = /\\g2printh\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string14_GoToMyPC_greyware_tool_keyword = /\\g2svc\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string15_GoToMyPC_greyware_tool_keyword = /\\goLoader\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string16_GoToMyPC_greyware_tool_keyword = /\\gosetup\[1\]\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string17_GoToMyPC_greyware_tool_keyword = /\\GoTo\sOpener\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string18_GoToMyPC_greyware_tool_keyword = /\\GoTo\\Logs\\goto\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string19_GoToMyPC_greyware_tool_keyword = /\\gotomon\.dll/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string20_GoToMyPC_greyware_tool_keyword = /\\gotomon_x64\.dll/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string21_GoToMyPC_greyware_tool_keyword = /\\GoToMyPC\.cab/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string22_GoToMyPC_greyware_tool_keyword = /\\GoToMyPC\\.{0,1000}\\.{0,1000}\\g2ldr\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string23_GoToMyPC_greyware_tool_keyword = /\\gotomypc\\g2pre\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string24_GoToMyPC_greyware_tool_keyword = /\\GoToMyPC\\g2svc\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string25_GoToMyPC_greyware_tool_keyword = /\\gotomypc_3944\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string26_GoToMyPC_greyware_tool_keyword = /\\GoToMyPCCrashHandler\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string27_GoToMyPC_greyware_tool_keyword = /\\GoToOpener\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string28_GoToMyPC_greyware_tool_keyword = /\\GoToOpener\[1\]\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string29_GoToMyPC_greyware_tool_keyword = /\\ICON_ID_GOTOMYPC/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string30_GoToMyPC_greyware_tool_keyword = /\\Local\\Temp\\LogMeInLogs\\GoToOpenerMsi\\/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string31_GoToMyPC_greyware_tool_keyword = /\\LogMeInLogs\\GoToOpenerMsi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string32_GoToMyPC_greyware_tool_keyword = /\\novaPDF11OEM\(x64\)\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string33_GoToMyPC_greyware_tool_keyword = /\\program\sfiles\s\(x86\)\\gotomypc\\g2tray\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string34_GoToMyPC_greyware_tool_keyword = /\\Programs\\GoToMyPC\.lnk/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string35_GoToMyPC_greyware_tool_keyword = /\\WOW6432Node\\Citrix\\GoToMyPc/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string36_GoToMyPC_greyware_tool_keyword = /\\x64\\monblanking\.sys/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string37_GoToMyPC_greyware_tool_keyword = /\<Data\>Installed\sGoToMyPC\<\/Data\>/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string38_GoToMyPC_greyware_tool_keyword = /\=http:\/\/www\.gotomypc\.com\/downloads\/viewer\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string39_GoToMyPC_greyware_tool_keyword = /api\-telemetry\.servers\.getgo\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string40_GoToMyPC_greyware_tool_keyword = /ApplicationName\'\>GoTo\sOpener/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string41_GoToMyPC_greyware_tool_keyword = /ApplicationName\'\>GoToMyPC\sCommunications/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string42_GoToMyPC_greyware_tool_keyword = /ApplicationName\'\>GoToMyPC\sHost\sLauncher/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string43_GoToMyPC_greyware_tool_keyword = /ApplicationName\'\>GoToMyPC\sViewer/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string44_GoToMyPC_greyware_tool_keyword = /cf3de8f800852490f39fdacbe74627564494235f/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string45_GoToMyPC_greyware_tool_keyword = /G2MScrUtil64\.exe.{0,1000}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string46_GoToMyPC_greyware_tool_keyword = /g2mui\.exe.{0,1000}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string47_GoToMyPC_greyware_tool_keyword = /GoTo\sMyPC\sInstaller\.exe/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string48_GoToMyPC_greyware_tool_keyword = /GOTO\sMYPC\sINSTALLER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string49_GoToMyPC_greyware_tool_keyword = /GoTo\sOpener\.exe\s/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string50_GoToMyPC_greyware_tool_keyword = /GOTO\sOPENER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string51_GoToMyPC_greyware_tool_keyword = /Goto\.exe.{0,1000}\?type\=crashpad\-handler/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string52_GoToMyPC_greyware_tool_keyword = /GoToMyPC_Installation\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string53_GoToMyPC_greyware_tool_keyword = /GoToMyPC_Setup\.log/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string54_GoToMyPC_greyware_tool_keyword = /GoToMyPCSetup_x64\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string55_GoToMyPC_greyware_tool_keyword = /GoToScrUtils\.exe.{0,1000}\/cr/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string56_GoToMyPC_greyware_tool_keyword = /launcher\-rest\-new\.live\.corecollab\.ucc\-prod\.eva\.goto\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string57_GoToMyPC_greyware_tool_keyword = /novaPDF11PrinterDriver\(x64\)\.msi/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string58_GoToMyPC_greyware_tool_keyword = /PollServer\spoll\.gotomypc\.com/ nocase ascii wide
        // Description: GoToMyPC is remote desktop software that allows users to access computers remotely using a web browser
        // Reference: https://www.gotomypc.com/
        $string59_GoToMyPC_greyware_tool_keyword = /ServiceName\'\>GoToMyPC/ nocase ascii wide

    condition:
        any of them
}


rule gpg_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'gpg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gpg"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: List gpg keys for privilege escalation
        // Reference: N/A
        $string1_gpg_greyware_tool_keyword = /gpg\s\-\-list\-keys/ nocase ascii wide

    condition:
        any of them
}


rule grep_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'grep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "grep"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string1_grep_greyware_tool_keyword = /grep\s\-.{0,1000}\s.{0,1000}DBPassword/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2_grep_greyware_tool_keyword = /grep\s.{0,1000}password\s\/var\/www/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string3_grep_greyware_tool_keyword = /grep\s.{0,1000}password\..{0,1000}\s\/etc\/.{0,1000}\.conf/ nocase ascii wide
        // Description: Look for users with a UID of 0
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4_grep_greyware_tool_keyword = /grep\s:0:\s\/etc\/passwd/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation.
        // Reference: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
        $string5_grep_greyware_tool_keyword = /grep\s\-i\spass\s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: https://gtfobins.github.io/
        $string6_grep_greyware_tool_keyword = /grep\s\-i\suser\s/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string7_grep_greyware_tool_keyword = /grep\s\-R\sdb_passwd/ nocase ascii wide
        // Description: Detects suspicious shell commands indicating the information gathering phase as preparation for the Privilege Escalation. # search for plain text user/passwords
        // Reference: N/A
        $string8_grep_greyware_tool_keyword = /grep\s\-roiE\s.{0,1000}password/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9_grep_greyware_tool_keyword = /grep.{0,1000}\|pwd\=\|passwd\=\|password\=/ nocase ascii wide
        // Description: search for passwords
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string10_grep_greyware_tool_keyword = /grep.{0,1000}password\|pwd\|pass/ nocase ascii wide
        // Description: search for passwords in memory and core dumps
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string11_grep_greyware_tool_keyword = /strings\s\-n\s.{0,1000}\s\/dev\/mem\s\|\sgrep\s\-i\spass/ nocase ascii wide

    condition:
        any of them
}


rule Guru_VPN__and__Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Guru VPN & Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Guru VPN & Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Guru_VPN__and__Proxy_greyware_tool_keyword = /knajdeaocbpmfghhmijicidfcmdgbdpm/ nocase ascii wide

    condition:
        any of them
}


rule Hide_My_IP_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hide My IP VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hide My IP VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hide_My_IP_VPN_greyware_tool_keyword = /keodbianoliadkoelloecbhllnpiocoi/ nocase ascii wide

    condition:
        any of them
}


rule HideAll_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HideAll VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HideAll VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_HideAll_VPN_greyware_tool_keyword = /amnoibeflfphhplmckdbiajkjaoomgnj/ nocase ascii wide

    condition:
        any of them
}


rule Hideman_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hideman VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hideman VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hideman_VPN_greyware_tool_keyword = /dbdbnchagbkhknegmhgikkleoogjcfge/ nocase ascii wide

    condition:
        any of them
}


rule history_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'history' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "history"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Removes the most recently logged command.
        // Reference: N/A
        $string1_history_greyware_tool_keyword = /history\s\-d\s\-2\s\&\&\shistory\s\-d\s\-1/ nocase ascii wide

    condition:
        any of them
}


rule HMA_VPN_Proxy_Unblocker_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'HMA VPN Proxy Unblocker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HMA VPN Proxy Unblocker"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_HMA_VPN_Proxy_Unblocker_greyware_tool_keyword = /poeojclicodamonabcabmapamjkkmnnk/ nocase ascii wide

    condition:
        any of them
}


rule Hola_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hola Free VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hola Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hola_Free_VPN_greyware_tool_keyword = /gkojfkhlekighikafcpjkiklfbnlmeio/ nocase ascii wide

    condition:
        any of them
}


rule Hola_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hola VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hola VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hola_VPN_greyware_tool_keyword = /kcdahmgmaagjhocpipbodaokikjkampi/ nocase ascii wide

    condition:
        any of them
}


rule Hotspot_Shield_Elite_VPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hotspot Shield Elite VPN Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hotspot Shield Elite VPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hotspot_Shield_Elite_VPN_Proxy_greyware_tool_keyword = /ejkaocphofnobjdedneohbbiilggdlbi/ nocase ascii wide

    condition:
        any of them
}


rule Hotspot_Shield_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hotspot Shield Free VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hotspot Shield Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hotspot_Shield_Free_VPN_greyware_tool_keyword = /nlbejmccbhkncgokjcmghpfloaajcffj/ nocase ascii wide

    condition:
        any of them
}


rule Hoxx_VPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hoxx VPN Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hoxx VPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hoxx_VPN_Proxy_greyware_tool_keyword = /nbcojefnccbanplpoffopkoepjmhgdgh/ nocase ascii wide

    condition:
        any of them
}


rule http_server_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'http.server' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "http.server"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: setup a simple http server
        // Reference: N/A
        $string1_http_server_greyware_tool_keyword = /python\s\-m\shttp\.server/ nocase ascii wide

    condition:
        any of them
}


rule Hub_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hub VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hub VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Hub_VPN_greyware_tool_keyword = /lneaocagcijjdpkcabeanfpdbmapcjjg/ nocase ascii wide

    condition:
        any of them
}


rule Hunter_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Hunter.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hunter.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string1_Hunter_io_greyware_tool_keyword = /curl\shttps:\/\/api\.hunter\.io\/v2\/domain\-search\?domain\=/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string2_Hunter_io_greyware_tool_keyword = /curl\shttps:\/\/api\.hunter\.io\/v2\/email\-finder\?domain\=/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string3_Hunter_io_greyware_tool_keyword = /curl\shttps:\/\/api\.hunter\.io\/v2\/email\-verifier\?email\=/ nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string4_Hunter_io_greyware_tool_keyword = /https:\/\/api\.hunter\.io\// nocase ascii wide
        // Description: used by attacker and pentester while gathering information. Hunter lets you find email addresses in seconds and connect with the people that matter for your business
        // Reference: https://hunter.io/
        $string5_Hunter_io_greyware_tool_keyword = /https:\/\/hunter\.io\// nocase ascii wide

    condition:
        any of them
}


rule icalcs_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'icalcs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "icalcs"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1_icalcs_greyware_tool_keyword = /icacls\s\"C:\\windows\\system32\\config\\SAM\"\s\/grant/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string2_icalcs_greyware_tool_keyword = /icacls\.exe\sC:\\Windows\\System32\\amsi\.dll\s\/grant\sadministrators:F/ nocase ascii wide

    condition:
        any of them
}


rule ifconfig_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ifconfig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ifconfig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: change mac address with ifconfig
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_ifconfig_greyware_tool_keyword = /ifconfig\s.{0,1000}\shw\sether\s/ nocase ascii wide
        // Description: changing mac address with ifconfig
        // Reference: N/A
        $string2_ifconfig_greyware_tool_keyword = /ifconfig\s.{0,1000}\shw\sether\s.{0,1000}:.{0,1000}:/ nocase ascii wide

    condition:
        any of them
}


rule iNinja_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'iNinja VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iNinja VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_iNinja_VPN_greyware_tool_keyword = /ookhnhpkphagefgdiemllfajmkdkcaim/ nocase ascii wide

    condition:
        any of them
}


rule IP_Unblock_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IP Unblock' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IP Unblock"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_IP_Unblock_greyware_tool_keyword = /lochiccbgeohimldjooaakjllnafhaid/ nocase ascii wide

    condition:
        any of them
}


rule ip_api_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ip-api.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ip-api.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: get public ip address
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1_ip_api_com_greyware_tool_keyword = /www\.ip\-api\.com/ nocase ascii wide

    condition:
        any of them
}


rule ip_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ip' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ip"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: changing mac address with ip
        // Reference: N/A
        $string1_ip_greyware_tool_keyword = /ip\sl\sset\sdev\s.{0,1000}\saddress\s.{0,1000}:.{0,1000}:/ nocase ascii wide

    condition:
        any of them
}


rule IPBurger_Proxy__and__VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'IPBurger Proxy & VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPBurger Proxy & VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_IPBurger_Proxy__and__VPN_greyware_tool_keyword = /kchocjcihdgkoplngjemhpplmmloanja/ nocase ascii wide

    condition:
        any of them
}


rule ipscan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ipscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ipscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string1_ipscan_greyware_tool_keyword = /\s\-jar\sipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string2_ipscan_greyware_tool_keyword = /\/AppFiles\/ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string3_ipscan_greyware_tool_keyword = /\/ipscan\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string4_ipscan_greyware_tool_keyword = /\/ipscan_.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string5_ipscan_greyware_tool_keyword = /\/ipscan2\-binary\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string6_ipscan_greyware_tool_keyword = /\/ipscan\-any\-.{0,1000}\.jar/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string7_ipscan_greyware_tool_keyword = /\\Angry\sIP\sScanner\.app/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string8_ipscan_greyware_tool_keyword = /\\ipscan\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string9_ipscan_greyware_tool_keyword = /\\ipscan221\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string10_ipscan_greyware_tool_keyword = /\\ipscan\-crash\.txt/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string11_ipscan_greyware_tool_keyword = /ipscan\s1.{0,1000}\.255/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string12_ipscan_greyware_tool_keyword = /ipscan\s10\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string13_ipscan_greyware_tool_keyword = /ipscan\s172\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string14_ipscan_greyware_tool_keyword = /ipscan\s192\.168\./ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string15_ipscan_greyware_tool_keyword = /ipscan\.exe\s\-/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string16_ipscan_greyware_tool_keyword = /ipscan\-win64\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Angry IP Scanner - fast and friendly network scanner - abused by a lot ransomware actors
        // Reference: https://github.com/angryip/ipscan
        $string17_ipscan_greyware_tool_keyword = /MacOS\/ipscan\s\-/ nocase ascii wide

    condition:
        any of them
}


rule iptables_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'iptables' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iptables"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string1_iptables_greyware_tool_keyword = /chkconfig\soff\sip6tables/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string2_iptables_greyware_tool_keyword = /chkconfig\soff\siptables/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string3_iptables_greyware_tool_keyword = /service\sip6tables\sstop/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string4_iptables_greyware_tool_keyword = /service\siptables\sstop/ nocase ascii wide

    condition:
        any of them
}


rule ipv4_myip_wtf_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ipv4.myip.wtf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ipv4.myip.wtf"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: get public ip address. Used by disctopia-c2
        // Reference: https://github.com/3ct0s/disctopia-c2/blob/main/libraries/disctopia.py
        $string1_ipv4_myip_wtf_greyware_tool_keyword = /https:\/\/ipv4\.myip\.wtf\/text/ nocase ascii wide

    condition:
        any of them
}


rule ivy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ivy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ivy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string1_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.png\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string2_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.hta\s\-url\shttp:.{0,1000}\s\-delivery\shta\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string3_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js\s\-url\shttp.{0,1000}\s\-delivery\sbits\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string4_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.txt\s\-url\shttp.{0,1000}\s\-delivery\smacro\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string5_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.xsl\s\-url\shttp.{0,1000}\s\-delivery\sxsl\s\-stageless/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string6_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.c\s\-Ix86\s.{0,1000}\.c\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string7_ivy_greyware_tool_keyword = /\s\-Ix64\s.{0,1000}\.vba\s\-Ix86\s.{0,1000}\.vba\s\-P\sInject\s\-O\s/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string8_ivy_greyware_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string9_ivy_greyware_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-process64\s.{0,1000}\.exe\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string10_ivy_greyware_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sInject\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string11_ivy_greyware_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string12_ivy_greyware_tool_keyword = /\s\-stageless\s\-Ix64\s.{0,1000}\.bin\s\-Ix86\s.{0,1000}\.bin\s\-P\sLocal\s\-unhook\s\-O\s.{0,1000}\.js/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string13_ivy_greyware_tool_keyword = /\.\/Ivy\s\-/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string14_ivy_greyware_tool_keyword = /\/Ivy\/Cryptor/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string15_ivy_greyware_tool_keyword = /\/Ivy\/Loader\// nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string16_ivy_greyware_tool_keyword = /\\Ivy\\Cryptor/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string17_ivy_greyware_tool_keyword = /\\Ivy\\Loader\\/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string18_ivy_greyware_tool_keyword = /go\sbuild\sIvy\.go/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string19_ivy_greyware_tool_keyword = /Ivy_1.{0,1000}_darwin_amd64/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string20_ivy_greyware_tool_keyword = /Ivy_1.{0,1000}_linux_amd64/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string21_ivy_greyware_tool_keyword = /Ivy_1.{0,1000}_windows_amd64\.exe/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string22_ivy_greyware_tool_keyword = /Ivy\-main\.zip/ nocase ascii wide
        // Description: Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory
        // Reference: https://github.com/optiv/Ivy
        $string23_ivy_greyware_tool_keyword = /optiv\/Ivy\.git/ nocase ascii wide

    condition:
        any of them
}


rule ldapsearch_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldapsearch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldapsearch"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ldapsearch to enumerate ldap
        // Reference: https://man7.org/linux/man-pages/man1/ldapsearch.1.html
        $string1_ldapsearch_greyware_tool_keyword = /ldapsearch\s.{0,1000}\sldap:\/\// nocase ascii wide
        // Description: ldapsearch to enumerate ldap
        // Reference: https://man7.org/linux/man-pages/man1/ldapsearch.1.html
        $string2_ldapsearch_greyware_tool_keyword = /ldapsearch\s\-x\s\-h\s.{0,1000}\s\-s\sbase/ nocase ascii wide
        // Description: ldapsearch to enumerate ldap
        // Reference: https://man7.org/linux/man-pages/man1/ldapsearch.1.html
        $string3_ldapsearch_greyware_tool_keyword = /ldapsearch\s\-h\s.{0,1000}\s\-x/ nocase ascii wide

    condition:
        any of them
}


rule ldifde_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ldifde' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ldifde"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: using ldifde.exe to export data from Active Directory to a .txt file in the Temp directory
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1_ldifde_greyware_tool_keyword = /ldifde\.exe\s\-f\s.{0,1000}\\temp\\.{0,1000}\.txt\s\-p\ssubtree/ nocase ascii wide

    condition:
        any of them
}


rule Lethean_Proxy_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Lethean Proxy VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lethean Proxy VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Lethean_Proxy_VPN_greyware_tool_keyword = /aigmfoeogfnljhnofglledbhhfegannp/ nocase ascii wide

    condition:
        any of them
}


rule linux_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'linux' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: fork bomb linux - denial-of-service attack wherein a process continually replicates itself to deplete available system resources slowing down or crashing the system due to resource starvation
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string1_linux_greyware_tool_keyword = /:\(\){:I:\s\&I/ nocase ascii wide

    condition:
        any of them
}


rule locate_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'locate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "locate"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Find sensitive files
        // Reference: N/A
        $string1_locate_greyware_tool_keyword = /locate\spassword\s\|\smore/ nocase ascii wide

    condition:
        any of them
}


rule ls_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ls' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ls"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: list remote pipename 
        // Reference: https://outflank.nl/blog/2023/10/19/listing-remote-named-pipes/
        $string1_ls_greyware_tool_keyword = /ls\s\\\\1.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}\\IPC\$\\/ nocase ascii wide

    condition:
        any of them
}


rule lyncsmash_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'lyncsmash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lyncsmash"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: default user agent used by lyncsmash.py - a collection of tools to enumerate and attack self-hosted Skype for Business and Microsoft Lync installations 
        // Reference: https://github.com/nyxgeek/lyncsmash
        $string1_lyncsmash_greyware_tool_keyword = /UCCAPI\/16\.0\.13328\.20130\sOC\/16\.0\.13426\.20234/ nocase ascii wide

    condition:
        any of them
}


rule macchanger_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'macchanger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macchanger"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: changing mac address with macchanger
        // Reference: N/A
        $string1_macchanger_greyware_tool_keyword = /macchanger\s\-r\s/ nocase ascii wide

    condition:
        any of them
}


rule Malus_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Malus VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Malus VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Malus_VPN_greyware_tool_keyword = /bdlcnpceagnkjnjlbbbcepohejbheilk/ nocase ascii wide

    condition:
        any of them
}


rule megatools_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'megatools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "megatools"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string1_megatools_greyware_tool_keyword = /\/megatools\.exe/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string2_megatools_greyware_tool_keyword = /\\megatools\-.{0,1000}\-win64\\/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string3_megatools_greyware_tool_keyword = /\\megatools\.exe/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string4_megatools_greyware_tool_keyword = /\\Users\\.{0,1000}\\AppData\\Local\\Temp\\.{0,1000}\.megatools\.cache/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string5_megatools_greyware_tool_keyword = /megatools\scopy\s\-l\s.{0,1000}\s\-r\s/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string6_megatools_greyware_tool_keyword = /megatools\sput\s/ nocase ascii wide

    condition:
        any of them
}


rule mkdir_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mkdir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mkdir"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: delete bash history
        // Reference: N/A
        $string1_mkdir_greyware_tool_keyword = /mkdir\s~\/\.bash_history/ nocase ascii wide

    condition:
        any of them
}


rule modproble_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'modproble' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "modproble"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string1_modproble_greyware_tool_keyword = /modprobe\s\-r/ nocase ascii wide
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string2_modproble_greyware_tool_keyword = /modprobe\s\-\-remove/ nocase ascii wide
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string3_modproble_greyware_tool_keyword = /modprobe\srmmod\s\-r/ nocase ascii wide

    condition:
        any of them
}


rule movefile64_exe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'movefile64.exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "movefile64.exe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string1_movefile64_exe_greyware_tool_keyword = /movefile64\.exe\s\/nobanner\s.{0,1000}\.dll\sC:\\Windows\\System32\\amsi\.dll/ nocase ascii wide

    condition:
        any of them
}


rule MpCmdRun_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'MpCmdRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MpCmdRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wipe currently stored definitions
        // Reference: N/A
        $string1_MpCmdRun_greyware_tool_keyword = /MpCmdRun\.exe\s\-RemoveDefinitions\s\-All/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string2_MpCmdRun_greyware_tool_keyword = /MpCmdRun\.exe.{0,1000}\s\-disable/ nocase ascii wide

    condition:
        any of them
}


rule mshta_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string1_mshta_greyware_tool_keyword = /mshta\shttp.{0,1000}\.hta/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string2_mshta_greyware_tool_keyword = /mshta\sjavascript:.{0,1000}script:https:/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string3_mshta_greyware_tool_keyword = /mshta\svbscript:Close\(Execute\(.{0,1000}script:https:\/\/.{0,1000}\.sct/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string4_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\shttp:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string5_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\shttps:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string6_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\sjavascript:.{0,1000}script:https:/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string7_mshta_greyware_tool_keyword = /mshta\.exe.{0,1000}\svbscript:Close\(Execute\(.{0,1000}script:https:\/\/.{0,1000}\.sct/ nocase ascii wide

    condition:
        any of them
}


rule Muscle_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Muscle VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Muscle VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Muscle_VPN_greyware_tool_keyword = /edknjdjielmpdlnllkdmaghlbpnmjmgb/ nocase ascii wide

    condition:
        any of them
}


rule My_Browser_Vpn_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'My Browser Vpn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "My Browser Vpn"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_My_Browser_Vpn_greyware_tool_keyword = /ppajinakbfocjfnijggfndbdmjggcmde/ nocase ascii wide

    condition:
        any of them
}


rule my_ip_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'my-ip.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "my-ip.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: abused by ransomwares
        // Reference: https://github.com/rivitna/Malware
        $string1_my_ip_io_greyware_tool_keyword = /https:\/\/api\.my\-ip\.io\/ip/ nocase ascii wide

    condition:
        any of them
}


rule myexternalip_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'myexternalip.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "myexternalip.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: return external ip address
        // Reference: https://myexternalip.com/raw
        $string1_myexternalip_com_greyware_tool_keyword = /https:\/\/myexternalip\.com\/raw/ nocase ascii wide

    condition:
        any of them
}


rule nbtscan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nbtscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: smb enumeration
        // Reference: https://github.com/charlesroelli/nbtscan
        $string1_nbtscan_greyware_tool_keyword = /nbtscan\s\-r\s.{0,1000}\/24/ nocase ascii wide

    condition:
        any of them
}


rule nbtstat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nbtstat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nbtstat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Displays the NetBIOS name table of the local computer. The status of registered indicates that the name is registered either by broadcast or with a WINS server.
        // Reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nbtstat
        $string1_nbtstat_greyware_tool_keyword = /nbtstat\s\-n/ nocase ascii wide

    condition:
        any of them
}


rule nc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Linux Persistence Shell cron
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_nc_greyware_tool_keyword = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\s\>\scron\s\&\&\scrontab\scron/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2_nc_greyware_tool_keyword = /\s\/bin\/nc\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\>\s.{0,1000}\scrontab\scron/ nocase ascii wide
        // Description: Netcat Realy on windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string3_nc_greyware_tool_keyword = /echo\snc\s\-l\s\-p\s.{0,1000}\s\>\s.{0,1000}\.bat/ nocase ascii wide
        // Description: Netcat Realy on windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string4_nc_greyware_tool_keyword = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s.{0,1000}\.bat/ nocase ascii wide
        // Description: Netcat Backdoor on Linux - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string5_nc_greyware_tool_keyword = /nc\s\-l\s\-p\s.{0,1000}\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: Netcat Backdoor on Windows - create a relay that sends packets from the local port to a netcat client connecte to the target ip on the targeted port
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string6_nc_greyware_tool_keyword = /nc\s\-l\s\-p\s.{0,1000}\s\-e\scmd\.exe/ nocase ascii wide
        // Description: Port scanner with netcat
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/NetcatCheatSheet.pdf
        $string7_nc_greyware_tool_keyword = /nc\s\-v\s\-n\s\-z\s\-w1\s.{0,1000}\-/ nocase ascii wide
        // Description: netcat common arguments
        // Reference: N/A
        $string8_nc_greyware_tool_keyword = /nc\s\-z\s\-v\s.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}


rule ncat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ncat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ncat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: reverse shell persistence
        // Reference: N/A
        $string1_ncat_greyware_tool_keyword = /\sncat\s.{0,1000}\s\-e\s\/bin\/bash.{0,1000}\|crontab/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2_ncat_greyware_tool_keyword = /ncat\s.{0,1000}\s\-p\s4444/ nocase ascii wide

    condition:
        any of them
}


rule Neo4j_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Neo4j' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Neo4j"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Neo4j queries - Computers in Unconstrained Delegations
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string1_Neo4j_greyware_tool_keyword = /MATCH\s\(c:Computer\s{unconsraineddelegation:true}\)\sRETURN\sc/ nocase ascii wide
        // Description: Neo4j queries - Computers AllowedToDelegate to other computers
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string2_Neo4j_greyware_tool_keyword = /MATCH\s\(c:Computer\).{0,1000}\(t:Computer\).{0,1000}\s.{0,1000}\-\[:AllowedToDelegate\].{0,1000}\sreturn\sp/ nocase ascii wide
        // Description: Neo4j queries - Potential SQL Admins
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string3_Neo4j_greyware_tool_keyword = /MATCH\sp\=\(u:User\)\-\[:SQLAdmin\].{0,1000}\(c:Computer\)\sreturn\sp/ nocase ascii wide
        // Description: Neo4j queries - Computers AllowedToDelegate to other computers
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string4_Neo4j_greyware_tool_keyword = /neo4j\sstart/ nocase ascii wide

    condition:
        any of them
}


rule net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Enumerate local accounts
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1_net_greyware_tool_keyword = /\\net\.exe\"\saccounts/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string2_net_greyware_tool_keyword = /\\net\.exe.{0,1000}\slocalgroup\sadmin/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string3_net_greyware_tool_keyword = /\\net\.exe.{0,1000}\ssessions/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string4_net_greyware_tool_keyword = /\\net\.exe.{0,1000}\sview\s.{0,1000}\/domain/ nocase ascii wide
        // Description: List active SMB session
        // Reference: N/A
        $string5_net_greyware_tool_keyword = /\\net1\ssessions/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string6_net_greyware_tool_keyword = /net\sgroup\s\"Domain\sAdmins\"\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string7_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string8_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string9_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string10_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query Domain Comtrollers Computers in the current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string11_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string12_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string13_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string14_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string15_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string16_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string17_net_greyware_tool_keyword = /net\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: Query users from domain admins in current domain
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string18_net_greyware_tool_keyword = /net\sgroup\s\/domain\s.{0,1000}Domain\sAdmins/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string19_net_greyware_tool_keyword = /net\sgroup\sadministrators\s\/domain/ nocase ascii wide
        // Description: discover local admins group
        // Reference: N/A
        $string20_net_greyware_tool_keyword = /net\slocalgroup\sadmin/ nocase ascii wide
        // Description: VoidCrypt ransomware
        // Reference: https://github.com/rivitna/Malware
        $string21_net_greyware_tool_keyword = /net\sstop\sMSSQL\$CONTOSO1_net_greyware_tool_keyword/ nocase ascii wide
        // Description: manipulation of an hidden local account with the net command
        // Reference: N/A
        $string22_net_greyware_tool_keyword = /net\suser\s.{0,1000}\$.{0,1000}\s\// nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string23_net_greyware_tool_keyword = /net\sview\s\/all\s\/domain/ nocase ascii wide
        // Description: adding a user to a privileged group. This action can be used by adversaries to maintain unauthorized access or escalate privileges within the targeted environment.
        // Reference: N/A
        $string24_net_greyware_tool_keyword = /net.{0,1000}\sgroup\sAdministrator.{0,1000}\s\/add\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string25_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string26_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string27_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string28_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string29_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string30_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string31_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string32_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string33_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string34_net_greyware_tool_keyword = /net\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string35_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string36_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string37_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string38_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string39_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string40_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string41_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string42_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string43_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string44_net_greyware_tool_keyword = /net1\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: showing users in a privileged group. 
        // Reference: N/A
        $string45_net_greyware_tool_keyword = /net1\slocalgroup\sadmin/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string46_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Account\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string47_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Backup\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string48_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sComputers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string49_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Domain\sControllers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string50_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Enterprise\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string51_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Exchange\sTrusted\sSubsystem.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string52_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Microsoft\sExchange\sServers.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string53_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Print\sOperators.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string54_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Schema\sAdmins.{0,1000}\s\/domain/ nocase ascii wide
        // Description: display all domain names on the network
        // Reference: N/A
        $string55_net_greyware_tool_keyword = /net1\.exe.{0,1000}\sgroup\s.{0,1000}Server\sOperators.{0,1000}\s\/domain/ nocase ascii wide

    condition:
        any of them
}


rule netcat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netcat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netcat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: netcat shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string1_netcat_greyware_tool_keyword = /nc\s.{0,1000}\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: netcat shell listener
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string2_netcat_greyware_tool_keyword = /nc\s\-u\s\-lvp\s/ nocase ascii wide
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string3_netcat_greyware_tool_keyword = /ncat\s.{0,1000}\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4_netcat_greyware_tool_keyword = /ncat\s\-\-udp\s.{0,1000}\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: Netcat is a featured networking utility which reads and writes data across network connections
        // Reference: http://netcat.sourceforge.net/
        $string5_netcat_greyware_tool_keyword = /netCat/ nocase ascii wide
        // Description: Netcat is a featured networking utility which reads and writes data across network connections. using the TCP/IP protocol It is designed to be a reliable back-end tool that can be used directly or easily driven by other programs and scripts. At the same time. it is a feature-rich network debugging and exploration tool. since it can create almost any kind of connection you would need and has several interesting built-in capabilities
        // Reference: http://netcat.sourceforge.net/
        $string6_netcat_greyware_tool_keyword = /nc\s\-vz\s/ nocase ascii wide

    condition:
        any of them
}


rule netscan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string1_netscan_greyware_tool_keyword = /\/netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2_netscan_greyware_tool_keyword = /\\netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3_netscan_greyware_tool_keyword = /\\netscan\.lic/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4_netscan_greyware_tool_keyword = /\\netscan\.xml/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5_netscan_greyware_tool_keyword = /\\SoftPerfect\sNetwork\sScanner/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6_netscan_greyware_tool_keyword = /netscan_setup\.exe/ nocase ascii wide

    condition:
        any of them
}


rule netsh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: gathering information about network configurations
        // Reference: 
        $string1_netsh_greyware_tool_keyword = /netsh\sadvfirewall\sfirewall\sshow\srule\sname\=all/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string2_netsh_greyware_tool_keyword = /NetSh\sAdvfirewall\sset\sallprofiles\sstate\soff/ nocase ascii wide
        // Description: adding a executable in user appdata folder to the allowed programs
        // Reference: https://tria.ge/231006-ydmxjsfe5s/behavioral1/analog?proc=66
        $string3_netsh_greyware_tool_keyword = /netsh\sfirewall\sadd\sallowedprogram\s\"C:\\Users\\.{0,1000}\\AppData\\.{0,1000}\.exe\"\s\".{0,1000}\.exe\"\sENABLE/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string4_netsh_greyware_tool_keyword = /netsh\sfirewall\sset\sopmode\sdisable/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string5_netsh_greyware_tool_keyword = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,1000}\sconnectport\=.{0,1000}\sconnectaddress\=/ nocase ascii wide
        // Description: The actor has used the following commands to enable port forwarding [T1090] on the host
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6_netsh_greyware_tool_keyword = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,1000}listenaddress\=.{0,1000}\slistenport\=.{0,1000}connectaddress\=.{0,1000}connectport/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string7_netsh_greyware_tool_keyword = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenport\=/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string8_netsh_greyware_tool_keyword = /netsh\sinterface\sportproxy\sshow\sv4tov4/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string9_netsh_greyware_tool_keyword = /netsh\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string10_netsh_greyware_tool_keyword = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide

    condition:
        any of them
}


rule NetshRun_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NetshRun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshRun"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string1_NetshRun_greyware_tool_keyword = /\/netshrun\.c/ nocase ascii wide
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string2_NetshRun_greyware_tool_keyword = /netsh\.exe\sadd\shelper\s.{0,1000}\\temp\\.{0,1000}\.dll/ nocase ascii wide
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string3_NetshRun_greyware_tool_keyword = /netshrun\.dll/ nocase ascii wide
        // Description: Netsh.exe relies on extensions taken from Registry which means it may be used as a persistence and you go one step further extending netsh with a DLL allowing you to do whatever you want
        // Reference: https://github.com/gtworek/PSBits/blob/master/NetShRun
        $string4_NetshRun_greyware_tool_keyword = /PSBits.{0,1000}NetShRun/ nocase ascii wide

    condition:
        any of them
}


rule netstat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'netstat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netstat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may attempt to execute recon commands
        // Reference: N/A
        $string1_netstat_greyware_tool_keyword = /netstat\s\-ano/ nocase ascii wide
        // Description: View all active TCP connections and the TCP and UDP ports the host is listening on.
        // Reference: N/A
        $string2_netstat_greyware_tool_keyword = /netstat\s\-ant/ nocase ascii wide
        // Description: Adversaries may attempt to execute recon commands
        // Reference: N/A
        $string3_netstat_greyware_tool_keyword = /NETSTAT\.EXE.{0,1000}\s\-ano/ nocase ascii wide

    condition:
        any of them
}


rule ngrok_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ngrok' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ngrok"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_ngrok_greyware_tool_keyword = /\/ngrok\.exe/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2_ngrok_greyware_tool_keyword = /\\ngrok\.exe/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3_ngrok_greyware_tool_keyword = /LHOST\=0\.tcp\.ngrok\.io/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string4_ngrok_greyware_tool_keyword = /ngrok\stcp\s/ nocase ascii wide
        // Description: ngrok - abused by attackers for C2 usage
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string5_ngrok_greyware_tool_keyword = /tcp:\/\/0\.tcp\.ngrok\.io:/ nocase ascii wide

    condition:
        any of them
}


rule nircmd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nircmd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nircmd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string1_nircmd_greyware_tool_keyword = /\snircmd\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string2_nircmd_greyware_tool_keyword = /\snircmdc\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string3_nircmd_greyware_tool_keyword = /\/nircmd\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string4_nircmd_greyware_tool_keyword = /\/nircmd\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string5_nircmd_greyware_tool_keyword = /\/nircmdc\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string6_nircmd_greyware_tool_keyword = /\/nircmd\-x64\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string7_nircmd_greyware_tool_keyword = /\\nircmd\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string8_nircmd_greyware_tool_keyword = /\\nircmd\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string9_nircmd_greyware_tool_keyword = /\\nircmdc\.exe/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string10_nircmd_greyware_tool_keyword = /\\nircmd\-x64\.zip/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string11_nircmd_greyware_tool_keyword = /nircmd\.exe\s/ nocase ascii wide
        // Description: Nirsoft tool - NirCmd is a small command-line utility that allows you to do some useful tasks without displaying any user interface
        // Reference: https://www.nirsoft.net/utils/nircmd.html
        $string12_nircmd_greyware_tool_keyword = /nircmdc\.exe\s/ nocase ascii wide

    condition:
        any of them
}


rule nirsoft_tools_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nirsoft tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nirsoft tools"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: NirSoft is a legitimate software company that develops system utilities for Windows. Some of its tools can be used by malicious actors to recover passwords harvest sensitive information and conduct password attacks.
        // Reference: N/A
        $string1_nirsoft_tools_greyware_tool_keyword = /https:\/\/www\.nirsoft\.net\/toolsdownload\// nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string2_nirsoft_tools_greyware_tool_keyword = /https:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.exe/ nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string3_nirsoft_tools_greyware_tool_keyword = /https:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.zip/ nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string4_nirsoft_tools_greyware_tool_keyword = /https:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.exe/ nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string5_nirsoft_tools_greyware_tool_keyword = /https:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}


rule nltest_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nltest' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nltest"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string1_nltest_greyware_tool_keyword = /nltest\s\/all_trusts/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string2_nltest_greyware_tool_keyword = /nltest\s\/dclist/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: N/A
        $string3_nltest_greyware_tool_keyword = /nltest\s\/domain_trusts/ nocase ascii wide
        // Description: enumerate domain trusts with nltest
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4_nltest_greyware_tool_keyword = /nltest\s\-dsgetdc/ nocase ascii wide

    condition:
        any of them
}


rule nmap_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'nmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nmap"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string1_nmap_greyware_tool_keyword = /\.\/nmap/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string2_nmap_greyware_tool_keyword = /\.\/test\/nmap.{0,1000}\/.{0,1000}\.nse/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string3_nmap_greyware_tool_keyword = /\/Nmap\/folder\/check15/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string4_nmap_greyware_tool_keyword = /\/Nmap\/folder\/check16/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string5_nmap_greyware_tool_keyword = /\/Nmap\/folder\/check17/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://nmap.org/book/nse-usage.html
        $string6_nmap_greyware_tool_keyword = /\/nmaplowercheck15/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string7_nmap_greyware_tool_keyword = /\/nmaplowercheck16/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string8_nmap_greyware_tool_keyword = /\/nmaplowercheck17/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string9_nmap_greyware_tool_keyword = /\/nmap\-nse\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string10_nmap_greyware_tool_keyword = /\/nmap\-scada/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string11_nmap_greyware_tool_keyword = /\/NmapUpperCheck15/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string12_nmap_greyware_tool_keyword = /\/NmapUpperCheck16/ nocase ascii wide
        // Description: Nmap (Network Mapper) is a free and open source utility for network discovery and security auditing
        // Reference: https://github.com/nmap/nmap/blob/635675b1430a89e950f71112d3bfc74feee4b19a/nselib/http.lua#L2600
        $string13_nmap_greyware_tool_keyword = /\/NmapUpperCheck17/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string14_nmap_greyware_tool_keyword = /\/nmap\-vulners/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string15_nmap_greyware_tool_keyword = /\/nse_install\// nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string16_nmap_greyware_tool_keyword = /\/nse\-install\.git/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string17_nmap_greyware_tool_keyword = /\/s4n7h0\/NSE/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string18_nmap_greyware_tool_keyword = /\\nmap\.exe.{0,1000}\/24/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string19_nmap_greyware_tool_keyword = /b4ldr\/nse\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string20_nmap_greyware_tool_keyword = /external\-nse\-script\-library/ nocase ascii wide
        // Description: Nmap Scan Every Interface that is Assigned an IP address
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string21_nmap_greyware_tool_keyword = /ifconfig\s\-a\s\|\sgrep\s.{0,1000}\s\|\sxargs\snmap\s\-/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string22_nmap_greyware_tool_keyword = /nmap\s\-/ nocase ascii wide
        // Description: check exploit for CVEs with nmap
        // Reference: https://nmap.org/
        $string23_nmap_greyware_tool_keyword = /nmap\s.{0,1000}\s\-\-script\=.{0,1000}\.nse/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string24_nmap_greyware_tool_keyword = /nmap\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string25_nmap_greyware_tool_keyword = /nmap\-elasticsearch\-nse/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string26_nmap_greyware_tool_keyword = /nse_install\.py/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string27_nmap_greyware_tool_keyword = /nse\-insall\-0\.0\.1/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string28_nmap_greyware_tool_keyword = /nse\-install\s/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string29_nmap_greyware_tool_keyword = /nse\-install\-master/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string30_nmap_greyware_tool_keyword = /OCSAF\/freevulnsearch/ nocase ascii wide
        // Description: Nmap Privilege Escalation
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string31_nmap_greyware_tool_keyword = /os\.execute\(.{0,1000}\/bin\/.{0,1000}nmap\s\-\-script\=\$/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string32_nmap_greyware_tool_keyword = /psc4re\/NSE\-scripts/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string33_nmap_greyware_tool_keyword = /remiflavien1\/nse\-install/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string34_nmap_greyware_tool_keyword = /shadawck\/nse\-install/ nocase ascii wide
        // Description: Install and update external NSE script for nmap
        // Reference: https://github.com/shadawck/nse-install
        $string35_nmap_greyware_tool_keyword = /takeshixx\/nmap\-scripts/ nocase ascii wide
        // Description: When Nmap is used on Windows systems. it can perform various types of scans such as TCP SYN scans. UDP scans. and service/version detection. These scans enable the identification of open ports. services running on those ports. and potential vulnerabilities in target systems.
        // Reference: N/A
        $string36_nmap_greyware_tool_keyword = /zenmap\.exe/ nocase ascii wide
        // Description: ZMap is a fast single packet network scanner designed for Internet-wide network surveys. On a typical desktop computer with a gigabit Ethernet connection. ZMap is capable scanning the entire public IPv4 address space in under 45 minutes. With a 10gigE connection and PF_RING. ZMap can scan the IPv4 address space in under 5 minutes. ZMap operates on GNU/Linux. Mac OS. and BSD. ZMap currently has fully implemented probe modules for TCP SYN scans. ICMP. DNS queries. UPnP. BACNET. and can send a large number of UDP probes. If you are looking to do more involved scans. e.g.. banner grab or TLS handshake. take a look at ZGrab. ZMaps sister project that performs stateful application-layer handshakes.
        // Reference: https://github.com/zmap/zmap
        $string37_nmap_greyware_tool_keyword = /zmap\s\-/ nocase ascii wide
        // Description: A very common tool. Network host vuln and port detector.
        // Reference: https://github.com/nmap/nmap
        $string38_nmap_greyware_tool_keyword = /nmap\s/ nocase ascii wide

    condition:
        any of them
}


rule NordVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'NordVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NordVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_NordVPN_greyware_tool_keyword = /fjoaledfpmneenckfbpdfhkmimnjocfa/ nocase ascii wide

    condition:
        any of them
}


rule Nsight_RMM_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nsight RMM"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string1_Nsight_RMM_greyware_tool_keyword = /\supload.{0,1000}\.systemmonitor\.eu\.com.{0,1000}\/command\/agentprocessor/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string2_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\debug\.log/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string3_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\staging/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string4_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\task_start\.js/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string5_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\unzip\.exe/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string6_Nsight_RMM_greyware_tool_keyword = /\\Advanced\sMonitoring\sAgent\\winagent\.exe/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string7_Nsight_RMM_greyware_tool_keyword = /\\Program\sFiles\s\(x86\)\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string8_Nsight_RMM_greyware_tool_keyword = /\\Program\sFiles\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string9_Nsight_RMM_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Advanced\sMonitoring\sAgent\.lnk/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string10_Nsight_RMM_greyware_tool_keyword = /Advanced\sMonitoring\sAgent\sHTTP\sRetriever\s1\.1/ nocase ascii wide

    condition:
        any of them
}


rule ntdsutil_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ntdsutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdsutil"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string1_ntdsutil_greyware_tool_keyword = /\\system32\.zip/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string2_ntdsutil_greyware_tool_keyword = /ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}create\sfull.{0,1000}\\temp/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string3_ntdsutil_greyware_tool_keyword = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}c:\\ProgramData/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string4_ntdsutil_greyware_tool_keyword = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}\s.{0,1000}ifm.{0,1000}\s.{0,1000}create\sfull\s.{0,1000}users\\public/ nocase ascii wide
        // Description: creating a full backup of the Active Directory database and saving it to the \temp directory
        // Reference: N/A
        $string5_ntdsutil_greyware_tool_keyword = /ntdsutil\.exe\s.{0,1000}ac\si\sntds.{0,1000}ifm.{0,1000}create\sfull\s.{0,1000}temp/ nocase ascii wide

    condition:
        any of them
}


rule Nucleus_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Nucleus VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nucleus VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Nucleus_VPN_greyware_tool_keyword = /ffhhkmlgedgcliajaedapkdfigdobcif/ nocase ascii wide

    condition:
        any of them
}


rule openssh_server_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'openssh server' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "openssh server"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Install OpenSSH Server service on windows - abused by attacker for persistant control
        // Reference: https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse?tabs=powershell#install-openssh-for-windows
        $string1_openssh_server_greyware_tool_keyword = /Add\-WindowsCapability\s\-Online\s\-Name\sOpenSSH\.Server/ nocase ascii wide

    condition:
        any of them
}


rule PAExec_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PAExec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PAExec"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string1_PAExec_greyware_tool_keyword = /\s\-csrc\sC:\\\\Windows\\\\notepad\.exe\s\-c\scmd\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string2_PAExec_greyware_tool_keyword = /\%SYSTEMROOT\%\\PAExec\-/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string3_PAExec_greyware_tool_keyword = /\/PAExec\.cpp/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string4_PAExec_greyware_tool_keyword = /\/paexec\.exe/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string5_PAExec_greyware_tool_keyword = /\/PAExec\.git/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string6_PAExec_greyware_tool_keyword = /\\PAExec\.cpp/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string7_PAExec_greyware_tool_keyword = /\\PAEXEC\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string8_PAExec_greyware_tool_keyword = /\\PAExecErr/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string9_PAExec_greyware_tool_keyword = /\\PAExecIn/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string10_PAExec_greyware_tool_keyword = /\\PAExecOut/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string11_PAExec_greyware_tool_keyword = /2FEB96F5\-08E6\-48A3\-B306\-794277650A08/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string12_PAExec_greyware_tool_keyword = /Description\'\>PAExec\sApplication/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string13_PAExec_greyware_tool_keyword = /\'Details\'\>paexec\sapplication/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string14_PAExec_greyware_tool_keyword = /paexec\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string15_PAExec_greyware_tool_keyword = /paexec\.exe\s\\\\/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string16_PAExec_greyware_tool_keyword = /PAExec\.exe\s\-u\s/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string17_PAExec_greyware_tool_keyword = /PAExec\-master\.zip/ nocase ascii wide
        // Description: PAExec is a freely-redistributable re-implementation of SysInternal/Microsoft's popular PsExec program
        // Reference: https://github.com/poweradminllc/PAExec
        $string18_PAExec_greyware_tool_keyword = /poweradminllc\/PAExec/ nocase ascii wide

    condition:
        any of them
}


rule passwd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'passwd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1_passwd_greyware_tool_keyword = /passwd.{0,1000}john/ nocase ascii wide

    condition:
        any of them
}


rule pastebin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pastebin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastebin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: pastebin raw access content - abused by malwares to retrieve payloads
        // Reference: pastebin.com
        $string1_pastebin_greyware_tool_keyword = /pastebin\.com.{0,1000}\/raw\/.{0,1000}\s/ nocase ascii wide
        // Description: pastebin raw access content - abused by malwares to retrieve payloads
        // Reference: pastebin.com
        $string2_pastebin_greyware_tool_keyword = /pastebin\.com.{0,1000}\/rw\// nocase ascii wide
        // Description: pastebin POST url - abused by malwares to exfiltrate informations
        // Reference: pastebin.com
        $string3_pastebin_greyware_tool_keyword = /pastebin\.com.{0,1000}api\/api_post\.php/ nocase ascii wide

    condition:
        any of them
}


rule pdbedit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pdbedit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pdbedit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Sets the smbpasswd listing format. It will make pdbedit list the users in the database - printing out the account fields in a format compatible with the smbpasswd file format.
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_pdbedit_greyware_tool_keyword = /pdbedit\s\-L\s\-v/ nocase ascii wide
        // Description: Enables the verbose listing format. It causes pdbedit to list the users in the database - printing out the account fields in a descriptive format
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2_pdbedit_greyware_tool_keyword = /pdbedit\s\-L\s\-w/ nocase ascii wide

    condition:
        any of them
}


rule phoenix_miner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'phoenix miner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phoenix miner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Phoenix Miner is a popular. efficient. fast. and cost-effective Ethereum miner with support for both AMD and Nvidia GPUs. It's intended to be used for legitimate cryptocurrency mining purposes.Attackers can secretly install Phoenix Miner on unsuspecting users' computers to mine cryptocurrency for themselves. This is often done by bundling the miner with other software or hiding it within malicious attachments or downloads. The computer then slow down due to the high CPU and GPU usage
        // Reference: N/A
        $string1_phoenix_miner_greyware_tool_keyword = /PhoenixMiner\.exe/ nocase ascii wide
        // Description: Phoenix Miner is a popular. efficient. fast. and cost-effective Ethereum miner with support for both AMD and Nvidia GPUs. It's intended to be used for legitimate cryptocurrency mining purposes.Attackers can secretly install Phoenix Miner on unsuspecting users' computers to mine cryptocurrency for themselves. This is often done by bundling the miner with other software or hiding it within malicious attachments or downloads. The computer then slow down due to the high CPU and GPU usage
        // Reference: N/A
        $string2_phoenix_miner_greyware_tool_keyword = /PhoenixMiner_.{0,1000}_Windows\\/ nocase ascii wide

    condition:
        any of them
}


rule php_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'php' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "php"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: php reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_php_greyware_tool_keyword = /php\s\-r\s.{0,1000}\$sock_php_greyware_tool_keyword\=fsockopen\(.{0,1000}exec\(.{0,1000}\/bin\/sh\s\-i\s\<\&3\s\>\&3\s2\>\&3/ nocase ascii wide

    condition:
        any of them
}


rule pktmon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pktmon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pktmon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: pktmon network diagnostics tool for Windows that can be used for packet capture - packet drop detection - packet filtering and counting.
        // Reference: https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon
        $string1_pktmon_greyware_tool_keyword = /pktmon\sstart/ nocase ascii wide

    condition:
        any of them
}


rule powershell_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "powershell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: alternativeto whoami
        // Reference: N/A
        $string1_powershell_greyware_tool_keyword = /\[System\.Environment\]::GetEnvironmentVariable\(\'username\'\)/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string2_powershell_greyware_tool_keyword = /\\powershell\.exe.{0,1000}\s\+\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string3_powershell_greyware_tool_keyword = /\\powershell\.exe.{0,1000}\s\+\=hidden/ nocase ascii wide
        // Description: command aiming to hide a file. It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string4_powershell_greyware_tool_keyword = /\\powershell\.exe.{0,1000}\s\=\shidden/ nocase ascii wide
        // Description: command aiming to hide a file.  It can be performed with  powershell on a WINDOWS machine with command option =hidden
        // Reference: N/A
        $string5_powershell_greyware_tool_keyword = /\\powershell\.exe.{0,1000}\s\=hidden/ nocase ascii wide
        // Description: adding a DNS over HTTPS server with powershell
        // Reference: https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientdohserveraddress?view=windowsserver2022-ps
        $string6_powershell_greyware_tool_keyword = /Add\-DnsClientDohServerAddress\s.{0,1000}\-ServerAddress\s/ nocase ascii wide
        // Description: Exclude powershell from defender detections
        // Reference: N/A
        $string7_powershell_greyware_tool_keyword = /Add\-MpPreference\s\-ExclusionProcess\s.{0,1000}\\Windows\\System32\\WindowsPowerShell\\v1\.0\\powershell\.exe/ nocase ascii wide
        // Description: allows all users to access all computers with a specified configuration
        // Reference: N/A
        $string8_powershell_greyware_tool_keyword = /Add\-PswaAuthorizationRule\s\-UsernName\s\\.{0,1000}\s\-ComputerName\s\\.{0,1000}\s\-ConfigurationName\s\\/ nocase ascii wide
        // Description: Deletes contents of recycle bin
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/-OMG-Credz-Plz
        $string9_powershell_greyware_tool_keyword = /Clear\-RecycleBin\s\-Force\s\-ErrorAction\sSilentlyContinue/ nocase ascii wide
        // Description: Find machine where the user has admin privs
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string10_powershell_greyware_tool_keyword = /Find\-LocalAdminAccess\s\-Verbose/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string11_powershell_greyware_tool_keyword = /gci\senv:USERNAME/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string12_powershell_greyware_tool_keyword = /gci\s\-h\sC:\\pagefile\.sys/ nocase ascii wide
        // Description: AppLocker Get AppLocker policy
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string13_powershell_greyware_tool_keyword = /Get\-AppLockerPolicy\s\-Effective\s/ nocase ascii wide
        // Description: set the DNS server configuration
        // Reference: N/A
        $string14_powershell_greyware_tool_keyword = /Get\-DhcpServerv4Scope\s\|\sSet\-DhcpServerv4OptionValue\s\-DnsServer\s/ nocase ascii wide
        // Description: Powerview Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string15_powershell_greyware_tool_keyword = /Get\-DomainUser\s\-KerberosPreuthNotRequired\s\-Verbose/ nocase ascii wide
        // Description: PowerView get Locally logged users on a machine
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string16_powershell_greyware_tool_keyword = /Get\-LoggedonLocal\s\-ComputerName\s/ nocase ascii wide
        // Description: Gets the status of antimalware software on the computer.
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string17_powershell_greyware_tool_keyword = /Get\-MpComputerStatus/ nocase ascii wide
        // Description: the command is used to discover the members of a specific domain group DNSAdmins which can provide an adversary with valuable information about the target environment. The knowledge of group members can be exploited by attackers to identify potential targets for privilege escalation or lateral movement within the network.
        // Reference: N/A
        $string18_powershell_greyware_tool_keyword = /Get\-NetGroupMember\s\-GroupName\s.{0,1000}DNSAdmins/ nocase ascii wide
        // Description: PowerView Find users with SPN
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string19_powershell_greyware_tool_keyword = /Get\-NetUser\s\-SPN/ nocase ascii wide
        // Description: Find local admins on the domain machines
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string20_powershell_greyware_tool_keyword = /Invoke\-EnumerateLocalAdmin\s\-Verbose/ nocase ascii wide
        // Description: Check local admin access for the current user where the targets are found
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string21_powershell_greyware_tool_keyword = /Invoke\-UserHunter\s\-CheckAccess/ nocase ascii wide
        // Description: C2 server to connect to a victim machine via reverse shell
        // Reference: https://github.com/reveng007/C2_Server
        $string22_powershell_greyware_tool_keyword = /Invoke\-WebRequest\sifconfig\.me\/ip.{0,1000}Content\.Trim\(\)/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string23_powershell_greyware_tool_keyword = /ls\senv:USERNAME/ nocase ascii wide
        // Description: Powershell reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string24_powershell_greyware_tool_keyword = /New\-Object\sSystem\.Net\.Sockets\.TCPClient\(.{0,1000}\$stream_powershell_greyware_tool_keyword\s\=\s\$client_powershell_greyware_tool_keyword\.GetStream\(\).{0,1000}\[byte\[\]\]\$bytes_powershell_greyware_tool_keyword\s\=\s0\.\.65535/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string25_powershell_greyware_tool_keyword = /powershell\s\-c\s.{0,1000}\\windows\\system32\\inetsrv\\appcmd\.exe\slist\sapppool\s\/\@t:/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string26_powershell_greyware_tool_keyword = /powershell\sNew\-ItemProperty\s\-Path\s.{0,1000}HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\-Name\sDisableAntiSpyware\s\-Value\s1\s\-PropertyType\sDWORD\s\-Force/ nocase ascii wide
        // Description: Windows Defender tampering technique 
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string27_powershell_greyware_tool_keyword = /powershell.{0,1000}Uninstall\-WindowsFeature\s\-Name\sWindows\-Defender\-GUI/ nocase ascii wide
        // Description: Adversaries may attempt to execute powershell script from known accessible location
        // Reference: N/A
        $string28_powershell_greyware_tool_keyword = /Powershell\.exe\s\s\-windowstyle\shidden\s\-nop\s\-ExecutionPolicy\sBypass\s\s\-Commmand\s.{0,1000}C:\\Users\\.{0,1000}\\AppData\\Roaming\\/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string29_powershell_greyware_tool_keyword = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string30_powershell_greyware_tool_keyword = /powershell\.exe\s\-exec\sbypass\s\-noni\s\-nop\s\-w\s1\s\-C.{0,1000}invoke_obfuscation/ nocase ascii wide
        // Description: command pattern used by crackmapexec by default A swiss army knife for pentesting networks
        // Reference: https://github.com/byt3bl33d3r/CrackMapExec
        $string31_powershell_greyware_tool_keyword = /powershell\.exe\s\-noni\s\-nop\s\-w\s1\s\-enc\s/ nocase ascii wide
        // Description: CrackMapExec behavior
        // Reference: https://github.com/Porchetta-Industries/CrackMapExec
        $string32_powershell_greyware_tool_keyword = /powershell\.exe\s\-NoP\s\-NoL\s\-sta\s\-NonI\s\-W\sHidden\s\-Exec\sBypass\s\-Enc\s/ nocase ascii wide
        // Description: list AV products with powershell
        // Reference: N/A
        $string33_powershell_greyware_tool_keyword = /root\/SecurityCenter2.{0,1000}\s\-ClassName\sAntiVirusProduct/ nocase ascii wide
        // Description: Disable scanning all downloaded files and attachments
        // Reference: N/A
        $string34_powershell_greyware_tool_keyword = /Set\-MpPreference\s\-DisableIOAVProtection\s\$true_powershell_greyware_tool_keyword/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string35_powershell_greyware_tool_keyword = /Set\-MpPreference\s\-DisableRealtimeMonitoring\s\$true_powershell_greyware_tool_keyword/ nocase ascii wide
        // Description: Disable AMSI (set to 0 to enable)
        // Reference: N/A
        $string36_powershell_greyware_tool_keyword = /Set\-MpPreference\s\-DisableScriptScanning\s1\s/ nocase ascii wide
        // Description: alternativeto whoami
        // Reference: N/A
        $string37_powershell_greyware_tool_keyword = /\[Environment\]::UserName/ nocase ascii wide
        // Description: Jenkins Abuse Without admin access
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string38_powershell_greyware_tool_keyword = /cmd\.exe\s\/c\sPowerShell\.exe\s\-Exec\sByPass\s\-Nol\s\-Enc\s/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string39_powershell_greyware_tool_keyword = /Get\-ADComputer\s\-Filter\s{TrustedForDelegation\s\-eq\s\$True_powershell_greyware_tool_keyword}/ nocase ascii wide
        // Description: AD Module Search for a particular string in attributes (admin)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string40_powershell_greyware_tool_keyword = /Get\-ADGroup\s\-Filter\s.{0,1000}Name\s\-like\s.{0,1000}admin/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string41_powershell_greyware_tool_keyword = /Get\-ADObject\s\-Filter\s{msDS\-AllowedToDelegateTo\s.{0,1000}\s\-Properties\smsDS\-AllowedToDelegateTo/ nocase ascii wide
        // Description: Enumerate shadow security principals mapped to a high priv group
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string42_powershell_greyware_tool_keyword = /Get\-ADObject\s\-SearchBase\s.{0,1000}CN\=Shadow\sPrincipal\sConfiguration.{0,1000}CN\=Services.{0,1000}\s\(Get\-ADRootDSE\)\.configurationNamingContext\)\s\|\sselect\s.{0,1000}msDS\-ShadowPrincipalSid/ nocase ascii wide
        // Description: AD module Enumerate users
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string43_powershell_greyware_tool_keyword = /Get\-ADUser\s\-Filter\s{DoesNotRequirePreAuth\s\-eq\s\$True_powershell_greyware_tool_keyword}\s\-Properties\sDoesNotRequirePreAuth/ nocase ascii wide
        // Description: AD Module Enumerate computers with Unconstrained Delegation
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string44_powershell_greyware_tool_keyword = /Get\-ADUser\s\-Filter\s{TrustedForDelegation\s\-eq\s\$True_powershell_greyware_tool_keyword}/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string45_powershell_greyware_tool_keyword = /Get\-DomainComputer\s\-TrustedToAuth/ nocase ascii wide
        // Description: AD Module Enumerate principals with Constrained Delegation enabled
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string46_powershell_greyware_tool_keyword = /Get\-DomainUser\s\-TrustedToAuth/ nocase ascii wide
        // Description: AD Module GroupPolicy - List of GPO in the domain
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string47_powershell_greyware_tool_keyword = /Get\-GPO\s\-All/ nocase ascii wide
        // Description: Find groups in the current domain (PowerView)
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string48_powershell_greyware_tool_keyword = /Get\-NetGroup\s\-FullData/ nocase ascii wide
        // Description: AD module Logon Script from remote IP
        // Reference: https://hideandsec.sh/books/cheatsheets-82c/page/active-directory
        $string49_powershell_greyware_tool_keyword = /Set\-ADObject\s\-SamAccountName\s.{0,1000}\s\-PropertyName\sscriptpath\s\-PropertyValue\s.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}


rule PowerSploit_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PowerSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSploit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string1_PowerSploit_greyware_tool_keyword = /Get\-NetForestCatalog/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string2_PowerSploit_greyware_tool_keyword = /Get\-NetForestDomain/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string3_PowerSploit_greyware_tool_keyword = /Get\-NetForestTrust/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string4_PowerSploit_greyware_tool_keyword = /Get\-NetSession/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string5_PowerSploit_greyware_tool_keyword = /Get\-NetShare/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string6_PowerSploit_greyware_tool_keyword = /Get\-NetSubnet/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string7_PowerSploit_greyware_tool_keyword = /Get\-RegistryAutoLogon/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string8_PowerSploit_greyware_tool_keyword = /Get\-SiteListPassword/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string9_PowerSploit_greyware_tool_keyword = /Get\-TimedScreenshot/ nocase ascii wide
        // Description: PowerSploit is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. PowerSploit is comprised of the following modules and scripts
        // Reference: https://github.com/PowerShellMafia/PowerSploit
        $string10_PowerSploit_greyware_tool_keyword = /Get\-UnquotedService/ nocase ascii wide

    condition:
        any of them
}


rule PP_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PP VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PP VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_PP_VPN_greyware_tool_keyword = /jljopmgdobloagejpohpldgkiellmfnc/ nocase ascii wide

    condition:
        any of them
}


rule Prime_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Prime VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Prime VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Prime_VPN_greyware_tool_keyword = /akkbkhnikoeojlhiiomohpdnkhbkhieh/ nocase ascii wide

    condition:
        any of them
}


rule Private_Internet_Access_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Private Internet Access' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Private Internet Access"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Private_Internet_Access_greyware_tool_keyword = /jplnlifepflhkbkgonidnobkakhmpnmh/ nocase ascii wide

    condition:
        any of them
}


rule Procdump_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Procdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Procdump"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string1_Procdump_greyware_tool_keyword = /procdump.{0,1000}lsass/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string2_Procdump_greyware_tool_keyword = /procdump.{0,1000}lsass/ nocase ascii wide
        // Description: dump lsass process with procdump
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
        $string3_Procdump_greyware_tool_keyword = /procdump64.{0,1000}lsass/ nocase ascii wide

    condition:
        any of them
}


rule processhacker_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'processhacker' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "processhacker"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string1_processhacker_greyware_tool_keyword = /\/processhacker\-.{0,1000}\-bin\.zip/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string2_processhacker_greyware_tool_keyword = /\/processhacker\/files\/latest\/download/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string3_processhacker_greyware_tool_keyword = /\\Process\sHacker\s2\\/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string4_processhacker_greyware_tool_keyword = /processhacker\-.{0,1000}\-sdk\.zip/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string5_processhacker_greyware_tool_keyword = /processhacker\-.{0,1000}\-setup\.exe/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string6_processhacker_greyware_tool_keyword = /processhacker\-.{0,1000}\-src\.zip/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string7_processhacker_greyware_tool_keyword = /ProcessHacker\.exe/ nocase ascii wide
        // Description: Interactions with a objects present in windows such as threads stack - handles - gpu - services ? can be used by attackers to dump process - create services  and process injection
        // Reference: https://processhacker.sourceforge.io/
        $string8_processhacker_greyware_tool_keyword = /ProcessHacker\.sln/ nocase ascii wide

    condition:
        any of them
}


rule procmon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'procmon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "procmon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Procmon used in user temp folder
        // Reference: N/A
        $string1_procmon_greyware_tool_keyword = /\\AppData\\Local\\Temp\\Procmon\.exe/ nocase ascii wide
        // Description: Procmon used in user temp folder
        // Reference: N/A
        $string2_procmon_greyware_tool_keyword = /\\AppData\\Local\\Temp\\Procmon64\.exe/ nocase ascii wide

    condition:
        any of them
}


rule Pron_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Pron VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pron VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Pron_VPN_greyware_tool_keyword = /nhfjkakglbnnpkpldhjmpmmfefifedcj/ nocase ascii wide

    condition:
        any of them
}


rule ProxFlow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ProxFlow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxFlow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_ProxFlow_greyware_tool_keyword = /aakchaleigkohafkfjfjbblobjifikek/ nocase ascii wide

    condition:
        any of them
}


rule Proxy_SwitchyOmega_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Proxy SwitchyOmega' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxy SwitchyOmega"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Proxy_SwitchyOmega_greyware_tool_keyword = /padekgcemlokbadohgkifijomclgjgif/ nocase ascii wide

    condition:
        any of them
}


rule Proxy_SwitchySharp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Proxy SwitchySharp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxy SwitchySharp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Proxy_SwitchySharp_greyware_tool_keyword = /dpplabbmogkhghncfbfdeeokoefdjegm/ nocase ascii wide

    condition:
        any of them
}


rule ProxyFlow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ProxyFlow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ProxyFlow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_ProxyFlow_greyware_tool_keyword = /llbhddikeonkpbhpncnhialfbpnilcnc/ nocase ascii wide

    condition:
        any of them
}


rule psexec_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'psexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psexec"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string1_psexec_greyware_tool_keyword = /\s\-accepteula\s\-nobanner\s\-d\scmd\.exe\s\/c\s/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string2_psexec_greyware_tool_keyword = /\.exe\s\-i\s\-s\scmd\.exe/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string3_psexec_greyware_tool_keyword = /\\PsExec\.exe/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string4_psexec_greyware_tool_keyword = /\\Windows\\Prefetch\\PSEXEC/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string5_psexec_greyware_tool_keyword = /PSEXEC\-.{0,1000}\.key/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string6_psexec_greyware_tool_keyword = /PsExec\[1\]\.exe/ nocase ascii wide
        // Description: Adversaries may place the PsExec executable in the temp directory and execute it from there as part of their offensive activities. By doing so. they can leverage PsExec to execute commands or launch processes on remote systems. enabling lateral movement. privilege escalation. or the execution of malicious payloads.
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string7_psexec_greyware_tool_keyword = /PsExec64\.exe/ nocase ascii wide
        // Description: PsExec is a legitimate Microsoft tool for remote administration. However. attackers can misuse it to execute malicious commands or software on other network machines. install persistent threats. and evade some security systems. 
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string8_psexec_greyware_tool_keyword = /PSEXECSVC/ nocase ascii wide
        // Description: .key file created and deleted on the target system
        // Reference: https://learn.microsoft.com/fr-fr/sysinternals/downloads/psexec
        $string9_psexec_greyware_tool_keyword = /PSEXECSVC\.EXE\-.{0,1000}\.pf/ nocase ascii wide

    condition:
        any of them
}


rule psloggedon_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'psloggedon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "psloggedon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PsLoggedOn is an applet that displays both the locally logged on users and users logged on via resources for either the local computer. or a remote one
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon
        $string1_psloggedon_greyware_tool_keyword = /PsLoggedon\.exe/ nocase ascii wide
        // Description: PsLoggedOn is an applet that displays both the locally logged on users and users logged on via resources for either the local computer. or a remote one
        // Reference: https://learn.microsoft.com/en-us/sysinternals/downloads/psloggedon
        $string2_psloggedon_greyware_tool_keyword = /PsLoggedon64\.exe/ nocase ascii wide

    condition:
        any of them
}


rule PureVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'PureVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PureVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_PureVPN_greyware_tool_keyword = /bfidboloedlamgdmenmlbipfnccokknp/ nocase ascii wide

    condition:
        any of them
}


rule Push_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Push VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Push VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Push_VPN_greyware_tool_keyword = /eidnihaadmmancegllknfbliaijfmkgo/ nocase ascii wide

    condition:
        any of them
}


rule py2exe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'py2exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "py2exe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string1_py2exe_greyware_tool_keyword = /\spy2exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string2_py2exe_greyware_tool_keyword = /\/py2exe\// nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string3_py2exe_greyware_tool_keyword = /\\py2exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string4_py2exe_greyware_tool_keyword = /py2exe\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string5_py2exe_greyware_tool_keyword = /py2exe.{0,1000}\.exe\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string6_py2exe_greyware_tool_keyword = /py2exe.{0,1000}\.msi\s/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string7_py2exe_greyware_tool_keyword = /py2exe.{0,1000}\.py/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string8_py2exe_greyware_tool_keyword = /py2exe\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string9_py2exe_greyware_tool_keyword = /py2exe\-.{0,1000}\.whl/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string10_py2exe_greyware_tool_keyword = /py2exe\.build_exe/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string11_py2exe_greyware_tool_keyword = /py2exe\.freeze/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string12_py2exe_greyware_tool_keyword = /py2exe\.git/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string13_py2exe_greyware_tool_keyword = /py2exe_setuptools\.py/ nocase ascii wide
        // Description: py2exe allows you to convert Python scripts into standalone executable files for Windows othen used by attacker
        // Reference: https://github.com/py2exe/py2exe
        $string14_py2exe_greyware_tool_keyword = /py2exe\-master\.zip/ nocase ascii wide

    condition:
        any of them
}


rule pyinstaller_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pyinstaller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyinstaller"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string1_pyinstaller_greyware_tool_keyword = /\/pyinstaller\// nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string2_pyinstaller_greyware_tool_keyword = /import\sPyInstaller/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string3_pyinstaller_greyware_tool_keyword = /install\spyinstaller/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string4_pyinstaller_greyware_tool_keyword = /pyinstaller\s.{0,1000}\.py/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string5_pyinstaller_greyware_tool_keyword = /pyinstaller\.exe/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string6_pyinstaller_greyware_tool_keyword = /pyinstaller\/tarball/ nocase ascii wide
        // Description: PyInstaller bundles a Python application and all its dependencies into a single package executable.
        // Reference: https://www.pyinstaller.org/
        $string7_pyinstaller_greyware_tool_keyword = /pyinstaller\-script\.py/ nocase ascii wide

    condition:
        any of them
}


rule pyshark_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'pyshark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshark"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string1_pyshark_greyware_tool_keyword = /\/pyshark\.git/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string2_pyshark_greyware_tool_keyword = /\\pyshark\\src\\/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string3_pyshark_greyware_tool_keyword = /import\spyshark/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string4_pyshark_greyware_tool_keyword = /KimiNewt\/pyshark/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string5_pyshark_greyware_tool_keyword = /pip\sinstall\spyshark/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string6_pyshark_greyware_tool_keyword = /pyshark\.FileCapture\(/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string7_pyshark_greyware_tool_keyword = /pyshark\.LiveCapture\(/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string8_pyshark_greyware_tool_keyword = /pyshark\.RemoteCapture\(/ nocase ascii wide

    condition:
        any of them
}


rule QuasarRAT_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'QuasarRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "QuasarRAT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Free. Open-Source Remote Administration Tool for Windows. Quasar is a fast and light-weight remote administration tool coded in C#. The usage ranges from user support through day-to-day administrative work to employee monitoring. Providing high stability and an easy-to-use user interface. Quasar is the perfect remote administration solution for you.
        // Reference: https://github.com/quasar/Quasar
        $string1_QuasarRAT_greyware_tool_keyword = /ping\s\-n\s10\slocalhost\s\>\snul/ nocase ascii wide

    condition:
        any of them
}


rule qwinsta_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'qwinsta' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "qwinsta"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enumerate rdp session on a remote server
        // Reference: N/A
        $string1_qwinsta_greyware_tool_keyword = /qwinsta\s\/server:/ nocase ascii wide

    condition:
        any of them
}


rule Radmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Radmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Radmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string1_Radmin_greyware_tool_keyword = /\/Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string2_Radmin_greyware_tool_keyword = /\/rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string3_Radmin_greyware_tool_keyword = /\\AppData\\Local\\Temp\\.{0,1000}_Radmin_3\..{0,1000}\.zip/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string4_Radmin_greyware_tool_keyword = /\\AppData\\Roaming\\Radmin/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string5_Radmin_greyware_tool_keyword = /\\Radmin\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string6_Radmin_greyware_tool_keyword = /\\RADMIN\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string7_Radmin_greyware_tool_keyword = /\\Radmin\\radmin\.rpb/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string8_Radmin_greyware_tool_keyword = /\\Radmin_Server_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string9_Radmin_greyware_tool_keyword = /\\Radmin_Viewer_.{0,1000}\.msi/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string10_Radmin_greyware_tool_keyword = /\\rserver3\.exe/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string11_Radmin_greyware_tool_keyword = /\\rsetup64\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string12_Radmin_greyware_tool_keyword = /\\rsl\.exe\s\/setup/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string13_Radmin_greyware_tool_keyword = /\\rsl\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string14_Radmin_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string15_Radmin_greyware_tool_keyword = /\\Start\sMenu\\Programs\\Radmin\sViewer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string16_Radmin_greyware_tool_keyword = /\\SysWOW64\\rserver30\\FamItrf2/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string17_Radmin_greyware_tool_keyword = /\\SysWOW64\\rserver30\\FamItrfc/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string18_Radmin_greyware_tool_keyword = /\\Windows\\SysWOW64\\rserver30\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string19_Radmin_greyware_tool_keyword = /HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Radmin\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string20_Radmin_greyware_tool_keyword = /netsh\sadvfirewall\sfirewall\sadd\srule\sname\=\"Radmin\sServer\s/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string21_Radmin_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Radmin\sViewer\s3\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string22_Radmin_greyware_tool_keyword = /radmin\s\/connect:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string23_Radmin_greyware_tool_keyword = /Radmin\sServer\sV3/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string24_Radmin_greyware_tool_keyword = /Radmin\sViewer\s3\\CHATLOGS\\/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string25_Radmin_greyware_tool_keyword = /Radmin\sViewer\s3\\rchatx\.dll/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string26_Radmin_greyware_tool_keyword = /radmin\.exe.{0,1000}\s\/connect:/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string27_Radmin_greyware_tool_keyword = /rserver3\s\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string28_Radmin_greyware_tool_keyword = /rserver3\s\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string29_Radmin_greyware_tool_keyword = /rserver3\.exe.{0,1000}\/start/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string30_Radmin_greyware_tool_keyword = /rserver3\.exe.{0,1000}\/stop/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string31_Radmin_greyware_tool_keyword = /Settings\sfor\sRadmin\sServer\.lnk/ nocase ascii wide
        // Description: Radmin is a remote control program that lets you work on another computer through your own
        // Reference: https://www.radmin.com/download/
        $string32_Radmin_greyware_tool_keyword = /Stop\sRadmin\sServer\.lnk/ nocase ascii wide

    condition:
        any of them
}


rule ratchatpt_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ratchatpt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ratchatpt"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C2 using openAI API
        // Reference: https://github.com/spartan-conseil/ratchatpt
        $string1_ratchatpt_greyware_tool_keyword = /https:\/\/api\.openai\.com\/v1\/files/ nocase ascii wide

    condition:
        any of them
}


rule rclone_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rclone' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rclone"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string1_rclone_greyware_tool_keyword = /\.rclone\.exe\sconfig/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string2_rclone_greyware_tool_keyword = /\/rclone\.exe/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string3_rclone_greyware_tool_keyword = /\\AppData\\Roaming\\rclone\\rclone\.conf/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string4_rclone_greyware_tool_keyword = /\\rclone\.exe/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string5_rclone_greyware_tool_keyword = /rclone\scopy\s.{0,1000}:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string6_rclone_greyware_tool_keyword = /rclone\.exe\sconfig\screate\sremote\smega\suser\s/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string7_rclone_greyware_tool_keyword = /rclone\.exe.{0,1000}\scopy\s.{0,1000}:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string8_rclone_greyware_tool_keyword = /rclone\.exe.{0,1000}\s\-l\s.{0,1000}\s.{0,1000}:/ nocase ascii wide

    condition:
        any of them
}


rule rderzh_VPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rderzh VPN Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rderzh VPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_rderzh_VPN_Proxy_greyware_tool_keyword = /oifjbnnafapeiknapihcmpeodaeblbkn/ nocase ascii wide

    condition:
        any of them
}


rule Red_Panda_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Red Panda VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Red Panda VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Red_Panda_VPN_greyware_tool_keyword = /plpmggfglncceinmilojdkiijhmajkjh/ nocase ascii wide

    condition:
        any of them
}


rule redpill_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'redpill' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redpill"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string1_redpill_greyware_tool_keyword = /\sGet\-AVStatus\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string2_redpill_greyware_tool_keyword = /\slist\-recycle\-bin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string3_redpill_greyware_tool_keyword = /\sps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string4_redpill_greyware_tool_keyword = /\.ps1\s\-sysinfo\sEnum/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string5_redpill_greyware_tool_keyword = /\/ps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string6_redpill_greyware_tool_keyword = /\/vbs2exe\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string7_redpill_greyware_tool_keyword = /\\credentials\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string8_redpill_greyware_tool_keyword = /\\Get\-AVStatus\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string9_redpill_greyware_tool_keyword = /\\ksjjhav\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string10_redpill_greyware_tool_keyword = /\\list\-recycle\-bin\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string11_redpill_greyware_tool_keyword = /\\OutlookEmails\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string12_redpill_greyware_tool_keyword = /\\ps2exe\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string13_redpill_greyware_tool_keyword = /\\Screenshot\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string14_redpill_greyware_tool_keyword = /\\Screenshot\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string15_redpill_greyware_tool_keyword = /\\Temp\\clipboard\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string16_redpill_greyware_tool_keyword = /\\Temp\\dave\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string17_redpill_greyware_tool_keyword = /\\Temp\\fsdgss\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string18_redpill_greyware_tool_keyword = /\\vbs2exe\.exe/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string19_redpill_greyware_tool_keyword = /BATtoEXEconverter\.bat/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string20_redpill_greyware_tool_keyword = /identify_offensive_tools\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string21_redpill_greyware_tool_keyword = /Mitre\-T1202\.ps1/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string22_redpill_greyware_tool_keyword = /Temp\\iprange\.log/ nocase ascii wide
        // Description: Assist reverse tcp shells in post-exploration tasks
        // Reference: https://github.com/r00t-3xp10it/redpill
        $string23_redpill_greyware_tool_keyword = /vbs2exe\.exe\s/ nocase ascii wide

    condition:
        any of them
}


rule reg_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'reg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reg"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string1_reg_greyware_tool_keyword = /copy\s.{0,1000}sam\.hive\s\\\\/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string2_reg_greyware_tool_keyword = /copy\s.{0,1000}system\.hive\s\\\\/ nocase ascii wide
        // Description: Allowing remote connections to this computer
        // Reference: N/A
        $string3_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal\sServer.{0,1000}\s\/v\sfDenyTSConnections\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: Hit F5 a bunch of times when you are at the RDP login screen
        // Reference: N/A
        $string4_reg_greyware_tool_keyword = /REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\sethc\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f/ nocase ascii wide
        // Description: At the login screen press Windows Key+U and you get a cmd.exe window as SYSTEM.
        // Reference: N/A
        $string5_reg_greyware_tool_keyword = /REG\sADD\s.{0,1000}HKLM\\SOFTWARE\\Microsoft\\Windows\sNT\\CurrentVersion\\Image\sFile\sExecution\sOptions\\utilman\.exe.{0,1000}\s\/t\sREG_SZ\s\/v\sDebugger\s\/d\s.{0,1000}\\windows\\system32\\cmd\.exe.{0,1000}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique disable windows defender
        // Reference: N/A
        $string6_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\s\/v\sDisableAntiSpyware\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string7_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender\".{0,1000}\/v\s.{0,1000}DisableAntiSpyware.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string8_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\s.{0,1000}DisableAntiVirus.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}1.{0,1000}\s\/f/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string9_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/v\sDisable.{0,1000}\s\/t\sREG_DWORD\s\/d\s1\s\/f/ nocase ascii wide
        // Description: Anti forensic - Disabling Prefetch
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string10_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session\sManager\\Memory\sManagement\\PrefetchParameters.{0,1000}\s\/v\sEnablePrefetcher\s\/t\sREG_DWORD\s\/f\s\/d\s0/ nocase ascii wide
        // Description: Blind ETW Windows Defender: zero out registry values corresponding to its ETW sessions
        // Reference: N/A
        $string11_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Control\\WMI\\Autologger\\DefenderApiLogger.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}0.{0,1000}\s\/f/ nocase ascii wide
        // Description: Disable Windows Defender Security Center
        // Reference: N/A
        $string12_reg_greyware_tool_keyword = /reg\sadd\s.{0,1000}HKLM\\System\\CurrentControlSet\\Services\\SecurityHealthService.{0,1000}\s\/v\s.{0,1000}Start.{0,1000}\s\/t\sREG_DWORD\s\/d\s.{0,1000}4.{0,1000}\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for lateral movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string13_reg_greyware_tool_keyword = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: This modification can be used to enable or disable the Restricted Admin mode for Remote Desktop Protocol (RDP) which has implications for lateral movement and privilege escalation
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string14_reg_greyware_tool_keyword = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sDisableRestrictedAdmin\s\/t\sREG_DWORD\s\/d\s0\s\/f/ nocase ascii wide
        // Description: This particular change is associated with the handling of LAN Manager (LM) hash storage which can affect the security of password storage on the system. This command can be used as part of credential access or defense evasion techniques
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string15_reg_greyware_tool_keyword = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sNoLMHash\s\/t\sREG_DWORD\s\/d\s\"0\"\s\/f/ nocase ascii wide
        // Description: Disable Cortex: Change the DLL to a random value
        // Reference: N/A
        $string16_reg_greyware_tool_keyword = /reg\sadd\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CryptSvc\\Parameters\s\/t\sREG_EXPAND_SZ\s\/v\sServiceDll\s\/d\s/ nocase ascii wide
        // Description: Disable Real Time Protection
        // Reference: N/A
        $string17_reg_greyware_tool_keyword = /reg\sdelete\s.{0,1000}HKLM\\Software\\Policies\\Microsoft\\Windows\sDefender.{0,1000}\s\/f/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string18_reg_greyware_tool_keyword = /reg\squery\s\"HKEY_LOCAL_MACHINE\\SOFTWARE\\MICROSOFT\\WINDOWS\sNT\\CURRENTVERSION\\WINLOGON\"\s\/v\sCACHEDLOGONSCOUNT/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string19_reg_greyware_tool_keyword = /reg\squery\shkcu\\software\\.{0,1000}\\putty\\session/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string20_reg_greyware_tool_keyword = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\LSA\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Check if LSASS is running in PPL
        // Reference: https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
        $string21_reg_greyware_tool_keyword = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: NetExec (a.k.a nxc) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks.
        // Reference: https://github.com/Pennyw0rth/NetExec
        $string22_reg_greyware_tool_keyword = /reg\squery\sHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\\s\/v\sRunAsPPL/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string23_reg_greyware_tool_keyword = /reg\squery\shklm\\software\\OpenSSH/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string24_reg_greyware_tool_keyword = /reg\squery\shklm\\software\\OpenSSH\\Agent/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string25_reg_greyware_tool_keyword = /reg\squery\shklm\\software\\realvnc/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string26_reg_greyware_tool_keyword = /reg\squery\shklm\\software\\realvnc\\Allusers/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string27_reg_greyware_tool_keyword = /reg\squery\shklm\\software\\realvnc\\Allusers\\vncserver/ nocase ascii wide
        // Description: Query the Windows registry sensitive informations
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string28_reg_greyware_tool_keyword = /reg\squery\shklm\\software\\realvnc\\vncserver/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string29_reg_greyware_tool_keyword = /reg\squery\sHKLM\\System\\CurrentControlSet\\Control\\LSA\s\/v\sLsaCfgFlags/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string30_reg_greyware_tool_keyword = /reg\squery\sHKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\s\/v\sUseLogonCredential/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string31_reg_greyware_tool_keyword = /reg\ssave\s\"HK\"L\"\"M\\s\"\"a\"\"m\"\"\swin32\.dll/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string32_reg_greyware_tool_keyword = /reg\ssave\s\"HK\"L\"\"M\\s\"\"ys\"\"t\"em\"\swin32\.exe/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string33_reg_greyware_tool_keyword = /reg\ssave\s\"HK.{0,1000}L.{0,1000}M\\s.{0,1000}ec.{0,1000}u.{0,1000}rit.{0,1000}y.{0,1000}\"\supdate\.exe/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\sam to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string34_reg_greyware_tool_keyword = /reg\ssave\shklm\\sam\s.{0,1000}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string35_reg_greyware_tool_keyword = /reg\ssave\sHKLM\\SAM\s.{0,1000}c:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string36_reg_greyware_tool_keyword = /reg\ssave\shklm\\sam\ssam/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\security to a .dat file
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string37_reg_greyware_tool_keyword = /reg\ssave\sHKLM\\SECURITY\s.{0,1000}c:/ nocase ascii wide
        // Description: saves a copy of the registry hive hklm\system to a .dat file
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string38_reg_greyware_tool_keyword = /reg\ssave\shklm\\system\s.{0,1000}\.dat/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string39_reg_greyware_tool_keyword = /reg\ssave\sHKLM\\SYSTEM\s.{0,1000}c:/ nocase ascii wide
        // Description: the commands are used to export the SAM and SYSTEM registry hives which contain sensitive Windows security data including hashed passwords for local accounts. By obtaining these hives an attacker can attempt to crack the hashes or use them in pass-the-hash attacks for unauthorized access.
        // Reference: N/A
        $string40_reg_greyware_tool_keyword = /reg\ssave\shklm\\system\ssystem/ nocase ascii wide

    condition:
        any of them
}


rule ren_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ren' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ren"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string1_ren_greyware_tool_keyword = /ren\sC:\\Windows\\System32\\amsi\.dll\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}


rule requests_ntlm_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'requests-ntlm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "requests-ntlm"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: HTTP NTLM Authentication for Requests Library
        // Reference: https://pypi.org/project/requests-ntlm/
        $string1_requests_ntlm_greyware_tool_keyword = /\sinstall\srequests_ntlm/ nocase ascii wide
        // Description: HTTP NTLM Authentication for Requests Library
        // Reference: https://pypi.org/project/requests-ntlm/
        $string2_requests_ntlm_greyware_tool_keyword = /from\srequests_ntlm\simport\sHttpNtlmAuth/ nocase ascii wide

    condition:
        any of them
}


rule rm_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rm"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: deleting bash history
        // Reference: N/A
        $string1_rm_greyware_tool_keyword = /rm\s\$HISTFILE_rm_greyware_tool_keyword/ nocase ascii wide
        // Description: deleting bash history
        // Reference: N/A
        $string2_rm_greyware_tool_keyword = /rm\s\.bash_history/ nocase ascii wide
        // Description: deleting log files
        // Reference: N/A
        $string3_rm_greyware_tool_keyword = /rm\s\/var\/log\/.{0,1000}\.log/ nocase ascii wide
        // Description: deleting bash history
        // Reference: N/A
        $string4_rm_greyware_tool_keyword = /rm\s~\/\.bash_history/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string5_rm_greyware_tool_keyword = /rm\s\-rf\s\.bash_history/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string6_rm_greyware_tool_keyword = /rm\s\-rf\s~\/\.bash_history/ nocase ascii wide

    condition:
        any of them
}


rule rmmod_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rmmod' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rmmod"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string1_rmmod_greyware_tool_keyword = /rmmod\s\-r/ nocase ascii wide
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string2_rmmod_greyware_tool_keyword = /rmmod\s\-\-remove/ nocase ascii wide
        // Description: Kernel modules are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. This rule identifies attempts to remove a kernel module.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_kernel_module_removal.toml
        $string3_rmmod_greyware_tool_keyword = /sudo\srmmod\s\-r/ nocase ascii wide

    condition:
        any of them
}


rule routerscan_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'routerscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "routerscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Router Scan is able to find and identify a variety of devices from large number of known routers on your internal network
        // Reference: https://en.kali.tools/?p=244
        $string1_routerscan_greyware_tool_keyword = /RouterScan\.exe/ nocase ascii wide

    condition:
        any of them
}


rule rpcclient_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rpcclient' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rpcclient"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tool for executing client side MS-RPC functions
        // Reference: https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
        $string1_rpcclient_greyware_tool_keyword = /rpcclient\s\-/ nocase ascii wide

    condition:
        any of them
}


rule rsync_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsync"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string1_rsync_greyware_tool_keyword = /rsync\s\-r\s.{0,1000}\s.{0,1000}\@.{0,1000}:/ nocase ascii wide
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string2_rsync_greyware_tool_keyword = /rsync\s\-r\s.{0,1000}\@.{0,1000}:.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}


rule ruby_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ruby' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruby"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ruby reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_ruby_greyware_tool_keyword = /ruby\s\-rsocket\s.{0,1000}TCPSocket\.open\(.{0,1000}exec\ssprintf.{0,1000}\/bin\/sh\s\-i\s/ nocase ascii wide

    condition:
        any of them
}


rule rundll32_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'rundll32' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rundll32"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string1_rundll32_greyware_tool_keyword = /rundll32.{0,1000}\.dll.{0,1000}a.{0,1000}\/p:/ nocase ascii wide
        // Description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
        // Reference: https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence
        $string2_rundll32_greyware_tool_keyword = /rundll32.{0,1000}\.dll.{0,1000}StartW/ nocase ascii wide

    condition:
        any of them
}


rule RustDesk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RustDesk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RustDesk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string1_RustDesk_greyware_tool_keyword = /\sRustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string2_RustDesk_greyware_tool_keyword = /\sstart\srustdesk:\/\// nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string3_RustDesk_greyware_tool_keyword = /\/home\/user\/rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string4_RustDesk_greyware_tool_keyword = /\/RustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string5_RustDesk_greyware_tool_keyword = /\/rustdesk\.git/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string6_RustDesk_greyware_tool_keyword = /\/rustdesk\/rustdesk\/releases\// nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string7_RustDesk_greyware_tool_keyword = /\\\.rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string8_RustDesk_greyware_tool_keyword = /\\\\RustDeskIddDriver/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string9_RustDesk_greyware_tool_keyword = /\\AppData\\Local\\rustdesk\\/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string10_RustDesk_greyware_tool_keyword = /\\config\\RustDesk\.toml/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string11_RustDesk_greyware_tool_keyword = /\\config\\RustDesk_local\./ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string12_RustDesk_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\RustDesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string13_RustDesk_greyware_tool_keyword = /\\librustdesk\.dll/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string14_RustDesk_greyware_tool_keyword = /\\ProgramData\\RustDesk\\/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string15_RustDesk_greyware_tool_keyword = /\\rustdesk\-.{0,1000}\-x86_64\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string16_RustDesk_greyware_tool_keyword = /\\RustDesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string17_RustDesk_greyware_tool_keyword = /\\RustDesk\.lnk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string18_RustDesk_greyware_tool_keyword = /\\RustDesk\\query/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string19_RustDesk_greyware_tool_keyword = /\\RustDeskIddDriver\\/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string20_RustDesk_greyware_tool_keyword = /\\test_rustdesk\.log/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string21_RustDesk_greyware_tool_keyword = /095e73fc4b115afd77e39a9389ff1eff6bdbff7a/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string22_RustDesk_greyware_tool_keyword = /HKEY_CLASSES_ROOT\\rustdesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string23_RustDesk_greyware_tool_keyword = /info\@rustdesk\.com/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string24_RustDesk_greyware_tool_keyword = /name\=\"RustDesk\sService\"/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string25_RustDesk_greyware_tool_keyword = /rs\-ny\.rustdesk\.com/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string26_RustDesk_greyware_tool_keyword = /RuntimeBroker_rustdesk\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string27_RustDesk_greyware_tool_keyword = /RustDesk\sService\sis\srunning/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string28_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.apk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string29_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.deb/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string30_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.dmg/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string31_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string32_RustDesk_greyware_tool_keyword = /rustdesk\-.{0,1000}\-win7\-install\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string33_RustDesk_greyware_tool_keyword = /RustDesk\.exe\s/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string34_RustDesk_greyware_tool_keyword = /RUSTDESK\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string35_RustDesk_greyware_tool_keyword = /RustDesk_hwcodec\./ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string36_RustDesk_greyware_tool_keyword = /RustDesk_install\.bat/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string37_RustDesk_greyware_tool_keyword = /rustdesk_portable\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string38_RustDesk_greyware_tool_keyword = /RustDesk_rCURRENT\.log/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string39_RustDesk_greyware_tool_keyword = /RustDesk_uninstall\.bat/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string40_RustDesk_greyware_tool_keyword = /RustDeskIddDriver\.cer/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string41_RustDesk_greyware_tool_keyword = /RustDeskIddDriver\.dll/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string42_RustDesk_greyware_tool_keyword = /rustdesk\-portable\-packer\.exe/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string43_RustDesk_greyware_tool_keyword = /sc\sstart\sRustDesk/ nocase ascii wide
        // Description: Rustdesk open suorce remote control software abused by scammers
        // Reference: https://github.com/rustdesk/rustdesk
        $string44_RustDesk_greyware_tool_keyword = /sc\sstop\sRustDesk/ nocase ascii wide

    condition:
        any of them
}


rule RusVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'RusVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RusVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_RusVPN_greyware_tool_keyword = /hipncndjamdcmphkgngojegjblibadbe/ nocase ascii wide

    condition:
        any of them
}


rule SaferVPN_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SaferVPN Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SaferVPN Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_SaferVPN_Proxy_greyware_tool_keyword = /cocfojppfigjeefejbpfmedgjbpchcng/ nocase ascii wide

    condition:
        any of them
}


rule samba_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'samba' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "samba"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The net command is one of the new features of Samba-3 and is an attempt to provide a useful tool for the majority of remote management operations necessary for common tasks. It is used by attackers to find users list
        // Reference: https://www.samba.org/samba/docs/old/Samba3-HOWTO/NetCommand.html
        $string1_samba_greyware_tool_keyword = /net\srpc\sgroup\smembers\s\'Domain\sUsers\'\s\-W\s/ nocase ascii wide

    condition:
        any of them
}


rule sc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get information about Windows Defender service
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string1_sc_greyware_tool_keyword = /\s\/c\ssc\squery\sWinDefend/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string2_sc_greyware_tool_keyword = /echo\sstart\s\>\s\\\\\.\\pipe\\winreg/ nocase ascii wide
        // Description: create service with netcat
        // Reference: https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/
        $string3_sc_greyware_tool_keyword = /sc\screate\s.{0,1000}nc\.exe\s\-.{0,1000}cmd\.exe/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string4_sc_greyware_tool_keyword = /sc\sdelete\sMBAMProtection/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string5_sc_greyware_tool_keyword = /sc\sdelete\sMBAMService/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string6_sc_greyware_tool_keyword = /sc\sqtriggerinfo\sRemoteRegistry/ nocase ascii wide
        // Description: start the RemoteRegistry service without Admin privileges
        // Reference: https://twitter.com/splinter_code/status/1715876413474025704
        $string7_sc_greyware_tool_keyword = /sc\sstart\sRemoteRegistry/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string8_sc_greyware_tool_keyword = /sc\sstop\sMBAMProtection/ nocase ascii wide
        // Description: stop AV script
        // Reference: https://thedfirreport.com/wp-content/uploads/2023/12/19208-013.png
        $string9_sc_greyware_tool_keyword = /sc\sstop\sMBAMService/ nocase ascii wide

    condition:
        any of them
}


rule schtasks_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'schtasks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "schtasks"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: view detailed information about all the scheduled tasks.
        // Reference: N/A
        $string1_schtasks_greyware_tool_keyword = /schtasks\s\/query\s\/v\s\/fo\sLIST/ nocase ascii wide

    condition:
        any of them
}


rule scp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'scp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "scp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string1_scp_greyware_tool_keyword = /scp\s.{0,1000}\s.{0,1000}\@.{0,1000}:/ nocase ascii wide
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string2_scp_greyware_tool_keyword = /scp\s.{0,1000}\@.{0,1000}:.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}


rule ScreenConnect_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ScreenConnect' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScreenConnect"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string1_ScreenConnect_greyware_tool_keyword = /:8040\/SetupWizard\.aspx/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string2_ScreenConnect_greyware_tool_keyword = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\ScreenConnect\sClient\s\(/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string3_ScreenConnect_greyware_tool_keyword = /\\CurrentControlSet\\Services\\ScreenConnect\s/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string4_ScreenConnect_greyware_tool_keyword = /\\Documents\\ConnectWiseControl\\Files/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string5_ScreenConnect_greyware_tool_keyword = /\\InventoryApplicationFile\\screenconnect\.cl/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string6_ScreenConnect_greyware_tool_keyword = /\\InventoryApplicationFile\\screenconnect\.wi/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string7_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\sClient\s\(/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string8_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Client\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string9_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.ClientService\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string10_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string11_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Core\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string12_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.InstallerActions\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string13_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.Windows\.dll/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string14_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string15_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string16_ScreenConnect_greyware_tool_keyword = /\\ScreenConnect\\Bin\\/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string17_ScreenConnect_greyware_tool_keyword = /\\TEMP\\ScreenConnect\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string18_ScreenConnect_greyware_tool_keyword = /\\Temp\\ScreenConnect\\.{0,1000}\\setup\.msi/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string19_ScreenConnect_greyware_tool_keyword = /\\Windows\\Temp\\ScreenConnect\\.{0,1000}\.cmd/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string20_ScreenConnect_greyware_tool_keyword = /\\Windows\\Temp\\ScreenConnect\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string21_ScreenConnect_greyware_tool_keyword = /\<Data\>ScreenConnect\sSoftware\<\/Data\>/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string22_ScreenConnect_greyware_tool_keyword = /\<Provider\sName\=\'ScreenConnect\sSecurity\sManager\'\/\>/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string23_ScreenConnect_greyware_tool_keyword = /\<Provider\sName\=\'ScreenConnect\sWeb\sServer\'\/\>/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string24_ScreenConnect_greyware_tool_keyword = /cmd\.exe.{0,1000}\\TEMP\\ScreenConnect\\.{0,1000}\.cmd/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string25_ScreenConnect_greyware_tool_keyword = /https:\/\/.{0,1000}\.screenconnect\.com\/Bin\/.{0,1000}\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string26_ScreenConnect_greyware_tool_keyword = /https:\/\/.{0,1000}\.screenconnect\.com\/Host/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string27_ScreenConnect_greyware_tool_keyword = /https:\/\/cloud\.screenconnect\.com\/\#\/trialtoinstance\?cookieValue\=/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string28_ScreenConnect_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\ScreenConnect\sClient/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string29_ScreenConnect_greyware_tool_keyword = /\-relay\.screenconnect\.com/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string30_ScreenConnect_greyware_tool_keyword = /ScreenConnect\sSoftware/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string31_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Client\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string32_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Client\.exe\.jar/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string33_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientService\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string34_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientService\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string35_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string36_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.CLIENTSETUP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string37_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.ClientUninstall\.vbs/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string38_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Core\.pdb/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string39_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.Server\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string40_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string41_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string42_ScreenConnect_greyware_tool_keyword = /SCREENCONNECT\.WINDOWSCLIENT\..{0,1000}\.pf/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string43_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string44_ScreenConnect_greyware_tool_keyword = /ScreenConnect\.WindowsInstaller\.dll/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string45_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,1000}_Release\.msi/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string46_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,1000}_Release\.tar\.gz/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string47_ScreenConnect_greyware_tool_keyword = /ScreenConnect_.{0,1000}_Release\.zip/ nocase ascii wide
        // Description: control remote servers - abused by threat actors
        // Reference: screenconnect.com
        $string48_ScreenConnect_greyware_tool_keyword = /server.{0,1000}\-relay\.screenconnect\.com/ nocase ascii wide
        // Description: ConnectWise Control formerly known as Screenconnect is a remote desktop software application.
        // Reference: https://screenconnect.connectwise.com/download
        $string49_ScreenConnect_greyware_tool_keyword = /\-web\.screenconnect\.com/ nocase ascii wide

    condition:
        any of them
}


rule sed_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sed' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sed"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allowing root login for ssh
        // Reference: N/A
        $string1_sed_greyware_tool_keyword = /sed\s\'s\/\#PermitRootLogin\sprohibit\-password\/PermitRootLogin\sYes\'\s\/etc\/ssh\/sshd_config/ nocase ascii wide

    condition:
        any of them
}


rule send_exploit_in_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'send.exploit.in' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "send.exploit.in"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: file-sharing platform used by ransomware groups
        // Reference: https://www.cisa.gov/sites/default/files/publications/aa22-321a_joint_csa_stopransomware_hive.pdf
        $string1_send_exploit_in_greyware_tool_keyword = /\/send\.exploit\.in\// nocase ascii wide

    condition:
        any of them
}


rule sendspace_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sendspace.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sendspace.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_sendspace_com_greyware_tool_keyword = /\shttps:\/\/www\.sendspace\.com\/file\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2_sendspace_com_greyware_tool_keyword = /https:\/\/.{0,1000}\.sendspace\.com\/upload/ nocase ascii wide

    condition:
        any of them
}


rule SentinelAgent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SentinelAgent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SentinelAgent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string1_SentinelAgent_greyware_tool_keyword = /\sDumpS1\.ps1/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string2_SentinelAgent_greyware_tool_keyword = /\/DumpS1\.ps1/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string3_SentinelAgent_greyware_tool_keyword = /\\DumpS1\.ps1/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string4_SentinelAgent_greyware_tool_keyword = /\\temp\\__SentinelAgentKernel\.dmp/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string5_SentinelAgent_greyware_tool_keyword = /\\temp\\__SentinelAgentUser\.dmp/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string6_SentinelAgent_greyware_tool_keyword = /DumpProcessPid\s\-targetPID\s.{0,1000}\s\-outputFile/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string7_SentinelAgent_greyware_tool_keyword = /TakeDump\s\-SentinelHelper\s.{0,1000}\s\-ProcessId\s.{0,1000}\s\-User\s.{0,1000}\s\-Kernel\s/ nocase ascii wide
        // Description: dump a process with SentinelAgent.exe
        // Reference: https://gist.github.com/adamsvoboda/8e248c6b7fb812af5d04daba141c867e
        $string8_SentinelAgent_greyware_tool_keyword = /Trying\sto\sdump\sSentinelAgent\sto\s/ nocase ascii wide

    condition:
        any of them
}


rule set_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'set' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "set"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Does not write any of the current session to the history log
        // Reference: N/A
        $string1_set_greyware_tool_keyword = /set\s\+o\shistory/ nocase ascii wide

    condition:
        any of them
}


rule SetupVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SetupVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetupVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_SetupVPN_greyware_tool_keyword = /oofgbpoabipfcfjapgnbbjjaenockbdp/ nocase ascii wide

    condition:
        any of them
}


rule sftp_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sftp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sftp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects the use of tools that copy files from or to remote systems
        // Reference: https://attack.mitre.org/techniques/T1105/
        $string1_sftp_greyware_tool_keyword = /sftp\s.{0,1000}\@.{0,1000}:.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}


rule shell_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string1_shell_greyware_tool_keyword = /\/bin\/sh\s\|\snc/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string2_shell_greyware_tool_keyword = /\/bin\/sh\s\-i\s\<\&3\s\>\&3\s2\>\&3/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string3_shell_greyware_tool_keyword = /rm\s\-f\sbackpipe.{0,1000}\smknod\s\/tmp\/backpipe\sp\s\&\&\snc\s/ nocase ascii wide
        // Description: Defense evasion technique In order to avoid detection at any point of the kill chain. attackers use several ways to disable anti-virus. disable Microsoft firewall and clear logs.
        // Reference: N/A
        $string4_shell_greyware_tool_keyword = /sc\sconfig\sWinDefend\sstart\=\sdisabled/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string5_shell_greyware_tool_keyword = /socket\(S.{0,1000}PF_INET.{0,1000}SOCK_STREAM.{0,1000}getprotobyname\(.{0,1000}tcp.{0,1000}\)\).{0,1000}if\(connect\(S.{0,1000}sockaddr_in\(\$p_shell_greyware_tool_keyword.{0,1000}inet_aton\(\$i_shell_greyware_tool_keyword\)\)\)\)/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string6_shell_greyware_tool_keyword = /STDIN\-\>fdopen\(\$c_shell_greyware_tool_keyword.{0,1000}r\).{0,1000}\$~\-\>fdopen\(\$c_shell_greyware_tool_keyword.{0,1000}w\).{0,1000}system\$__shell_greyware_tool_keyword\swhile\<\>/ nocase ascii wide
        // Description: Reverse Shell Command Line
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_shell_susp_rev_shells.yml
        $string7_shell_greyware_tool_keyword = /uname\s\-a.{0,1000}\sw.{0,1000}\sid.{0,1000}\s\/bin\/bash\s\-i/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string8_shell_greyware_tool_keyword = /schkconfig\soff\scbdaemon/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string9_shell_greyware_tool_keyword = /service\scbdaemon\sstop/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string10_shell_greyware_tool_keyword = /setenforce\s0/ nocase ascii wide

    condition:
        any of them
}


rule shred_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'shred' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "shred"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: deleting bash history
        // Reference: N/A
        $string1_shred_greyware_tool_keyword = /shred\s\$HISTFILE_shred_greyware_tool_keyword/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string2_shred_greyware_tool_keyword = /shred\s\-\-remove/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string3_shred_greyware_tool_keyword = /shred\s\-u/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string4_shred_greyware_tool_keyword = /shred\s\-z/ nocase ascii wide
        // Description: Malware or other files dropped or created on a system by an adversary may leave traces behind as to what was done within a network and how. Adversaries may remove these files over the course of an intrusion to keep their footprint low or remove them at the end as part of the post-intrusion cleanup process.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_file_deletion_via_shred.toml
        $string5_shred_greyware_tool_keyword = /shred\s\-\-zero/ nocase ascii wide

    condition:
        any of them
}


rule simplehttpserver_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'simplehttpserver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "simplehttpserver"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string1_simplehttpserver_greyware_tool_keyword = /\s\-m\sSimpleHTTPServer\s/ nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string2_simplehttpserver_greyware_tool_keyword = /import\sSimpleHTTPServer/ nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string3_simplehttpserver_greyware_tool_keyword = /python\s\-m\sSimpleHTTPServer/ nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string4_simplehttpserver_greyware_tool_keyword = /SimpleHTTPServer\.SimpleHTTPRequestHandler/ nocase ascii wide

    condition:
        any of them
}


rule skymen_info_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'skymen.info' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "skymen.info"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: used by attackers to find informations about a company users
        // Reference: https://www.skymem.info
        $string1_skymen_info_greyware_tool_keyword = /https:\/\/www\.skymem\.info\/srch\?q\=/ nocase ascii wide

    condition:
        any of them
}


rule smc_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'smc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smc"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string1_smc_greyware_tool_keyword = /smc\s\-disable\s\-mem/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string2_smc_greyware_tool_keyword = /smc\s\-disable\s\-ntp/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string3_smc_greyware_tool_keyword = /smc\s\-disable\s\-wss/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string4_smc_greyware_tool_keyword = /smc\s\-enable\s\-gem/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string5_smc_greyware_tool_keyword = /smc\.exe\s\-disable\s\-mem/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string6_smc_greyware_tool_keyword = /smc\.exe\s\-disable\s\-ntp/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string7_smc_greyware_tool_keyword = /smc\.exe\s\-disable\s\-wss/ nocase ascii wide
        // Description: Symantec Client Management Component or (smc.exe) is a command-line utility that can manage (enable - disable - export) different components of SEP
        // Reference: https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Antivirus/Symantec%20Endpoint%20Protection#threat-actor-ops-taops
        $string8_smc_greyware_tool_keyword = /smc\.exe\s\-enable\s\-gem/ nocase ascii wide

    condition:
        any of them
}


rule snmpcheck_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'snmpcheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpcheck"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: automate the process of gathering information of any devices with SNMP protocol support. like snmpwalk - snmpcheck allows you to enumerate the SNMP devices and places the output in a very human readable friendly format. It could be useful for penetration testing or systems monitoring
        // Reference: http://www.nothink.org/codes/snmpcheck/index.php
        $string1_snmpcheck_greyware_tool_keyword = /install\ssnmpcheck/ nocase ascii wide
        // Description: automate the process of gathering information of any devices with SNMP protocol support. like snmpwalk - snmpcheck allows you to enumerate the SNMP devices and places the output in a very human readable friendly format. It could be useful for penetration testing or systems monitoring
        // Reference: http://www.nothink.org/codes/snmpcheck/index.php
        $string2_snmpcheck_greyware_tool_keyword = /snmp\-check\s.{0,1000}\s\-c\spublic/ nocase ascii wide

    condition:
        any of them
}


rule snmpwalk_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'snmpwalk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "snmpwalk"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allows you to enumerate the SNMP devices and places the output in a very human readable friendly format
        // Reference: https://wiki.debian.org/SNMP
        $string1_snmpwalk_greyware_tool_keyword = /snmpwalk\s\s\-v1\s\-cpublic\s/ nocase ascii wide
        // Description: allows you to enumerate the SNMP devices and places the output in a very human readable friendly format
        // Reference: https://wiki.debian.org/SNMP
        $string2_snmpwalk_greyware_tool_keyword = /snmpwalk\s.{0,1000}\spublic\s.{0,1000}1\.3\.6\.1\./ nocase ascii wide
        // Description: allows you to enumerate the SNMP devices and places the output in a very human readable friendly format
        // Reference: https://wiki.debian.org/SNMP
        $string3_snmpwalk_greyware_tool_keyword = /snmpwalk\s\-c\spublic\s\-v1\s/ nocase ascii wide

    condition:
        any of them
}


rule socat_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'socat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "socat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string1_socat_greyware_tool_keyword = /socat\sexec:/ nocase ascii wide
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string2_socat_greyware_tool_keyword = /socat\sFILE:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\sTCP.{0,1000}:/ nocase ascii wide
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string3_socat_greyware_tool_keyword = /socat\sfile:.{0,1000}tty.{0,1000}raw.{0,1000}echo\=0\stcp\-listen:/ nocase ascii wide
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string4_socat_greyware_tool_keyword = /socat\s\-O\s\/tmp\// nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string5_socat_greyware_tool_keyword = /socat\sTCP4\-LISTEN:.{0,1000}\sfork\sTCP4:.{0,1000}:/ nocase ascii wide
        // Description: Shell spawning socat usage 
        // Reference: https://linuxfr.org/news/socat-un-outil-en-ligne-de-commande-pour-maitriser-vos-sockets
        $string6_socat_greyware_tool_keyword = /socat\stcp\-connect/ nocase ascii wide
        // Description: socat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string7_socat_greyware_tool_keyword = /socat\stcp\-connect:.{0,1000}:.{0,1000}\sexec:.{0,1000}bash\s\-li.{0,1000}.{0,1000}pty.{0,1000}stderr.{0,1000}setsid.{0,1000}sigint.{0,1000}sane/ nocase ascii wide
        // Description: socat reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string8_socat_greyware_tool_keyword = /socat\stcp\-connect:.{0,1000}:.{0,1000}\sexec:\/bin\/sh/ nocase ascii wide
        // Description: socat bind shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string9_socat_greyware_tool_keyword = /socat\sTCP\-LISTEN:.{0,1000}.{0,1000}reuseaddr.{0,1000}fork\sEXEC:\/bin\/sh/ nocase ascii wide

    condition:
        any of them
}


rule Social_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Social VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Social VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Social_VPN_greyware_tool_keyword = /igahhbkcppaollcjeaaoapkijbnphfhb/ nocase ascii wide

    condition:
        any of them
}


rule softperfect_networkscanner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'softperfect networkscanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "softperfect networkscanner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string1_softperfect_networkscanner_greyware_tool_keyword = /\s\/config:netscan\.xml\s/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2_softperfect_networkscanner_greyware_tool_keyword = /\snetscan\.exe\s/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3_softperfect_networkscanner_greyware_tool_keyword = /\.exe\s.{0,1000}\s\/hide\s.{0,1000}\s\/range:.{0,1000}\s\/auto:.{0,1000}\./ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4_softperfect_networkscanner_greyware_tool_keyword = /\.exe\s\/hide\s\/range:all/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5_softperfect_networkscanner_greyware_tool_keyword = /\.exe\s\/wakeall/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6_softperfect_networkscanner_greyware_tool_keyword = /\/netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string7_softperfect_networkscanner_greyware_tool_keyword = /\/netscan_linux\.tar\.gz/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string8_softperfect_networkscanner_greyware_tool_keyword = /\/netscan_portable\.zip/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string9_softperfect_networkscanner_greyware_tool_keyword = /\/netscan_setup\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string10_softperfect_networkscanner_greyware_tool_keyword = /\\netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string11_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_linux\.tar\.gz/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string12_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_portable\.zip/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string13_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_portable\\/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string14_softperfect_networkscanner_greyware_tool_keyword = /\\netscan_setup\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string15_softperfect_networkscanner_greyware_tool_keyword = /netscan\.exe\s\// nocase ascii wide
        // Description: SoftPerfect Network Scanner can ping computers scan ports discover shared folders and retrieve practically any information about network devices via WMI SNMP HTTP SSH and PowerShell
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string16_softperfect_networkscanner_greyware_tool_keyword = /SoftPerfect_.{0,1000}Patch_Keygen_v2.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}


rule Soul_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Soul VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Soul VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Soul_VPN_greyware_tool_keyword = /apcfdffemoinopelidncddjbhkiblecc/ nocase ascii wide

    condition:
        any of them
}


rule SpaceRunner_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'SpaceRunner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpaceRunner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string1_SpaceRunner_greyware_tool_keyword = /\/spacerunner\.exe/ nocase ascii wide
        // Description: enables the compilation of a C# program that will execute arbitrary PowerShell code without launching PowerShell processes through the use of runspace.
        // Reference: https://github.com/Mr-B0b/SpaceRunner
        $string2_SpaceRunner_greyware_tool_keyword = /\\spacerunner\.exe/ nocase ascii wide

    condition:
        any of them
}


rule Splashtop_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Splashtop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Splashtop"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string1_Splashtop_greyware_tool_keyword = /\.api\.splashtop\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string2_Splashtop_greyware_tool_keyword = /\.relay\.splashtop\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string3_Splashtop_greyware_tool_keyword = /\/Library\/Logs\/SPLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string4_Splashtop_greyware_tool_keyword = /\/SplashtopStreamer\/SPLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string5_Splashtop_greyware_tool_keyword = /\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string6_Splashtop_greyware_tool_keyword = /\\Splashtop\\Temp\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string7_Splashtop_greyware_tool_keyword = /\\Splashtop\\Temp\\log\\FTCLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string8_Splashtop_greyware_tool_keyword = /\\strwinclt\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string9_Splashtop_greyware_tool_keyword = /\\WOW6432Node\\Splashtop\sInc\.\\Splashtop\sRemote\sServer/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string10_Splashtop_greyware_tool_keyword = /CurrentVersion\\Uninstall\\Splashtop\sInc\.\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string11_Splashtop_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\Splashtop/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string12_Splashtop_greyware_tool_keyword = /Software\\Splashtop\sInc\.\\Splashtop/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string13_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\agent_log\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string14_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\SPLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string15_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\svcinfo\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string16_Splashtop_greyware_tool_keyword = /Splashtop\sRemote\\Server\\log\\sysinfo\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string17_Splashtop_greyware_tool_keyword = /Splashtop_Streamer_Windows_.{0,1000}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string18_Splashtop_greyware_tool_keyword = /Splashtop\-Splashtop\sStreamer\-/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://ruler-project.github.io/ruler-project/RULER/remote/Splashtop/
        $string19_Splashtop_greyware_tool_keyword = /SplashtopStreamer\..{0,1000}\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string20_Splashtop_greyware_tool_keyword = /SplashtopStreamer3500\.exe.{0,1000}\sprevercheck\s/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://hybrid-analysis.com/sample/18c10b0235bd341e065ac5c53ca04b68eaeacd98a120e043fb4883628baf644e/6267eb693836e7217b1a3c72
        $string21_Splashtop_greyware_tool_keyword = /www\.splashtop\.com\/remotecaRemoveVRootsISCHECKFORPRODUCTUPDATES/ nocase ascii wide

    condition:
        any of them
}


rule ss_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ss' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ss"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: replace netstat command - service listening
        // Reference: N/A
        $string1_ss_greyware_tool_keyword = /ss\s\-lntp/ nocase ascii wide

    condition:
        any of them
}


rule ssh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ssh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string1_ssh_greyware_tool_keyword = /bad\sclient\spublic\sDH\svalue/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string2_ssh_greyware_tool_keyword = /Corrupted\sMAC\son\sinput/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string3_ssh_greyware_tool_keyword = /error\sin\slibcrypto/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string4_ssh_greyware_tool_keyword = /fatal:\sbuffer_get_string:\sbad\sstring/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string5_ssh_greyware_tool_keyword = /incorrect\ssignature/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string6_ssh_greyware_tool_keyword = /invalid\scertificate\ssigning\skey/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string7_ssh_greyware_tool_keyword = /invalid\selliptic\scurve\svalue/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string8_ssh_greyware_tool_keyword = /Local:\scrc32\scompensation\sattack/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string9_ssh_greyware_tool_keyword = /unexpected\sbytes\sremain\safter\sdecoding/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string10_ssh_greyware_tool_keyword = /unexpected\sinternal\serror/ nocase ascii wide
        // Description: Detects suspicious SSH / SSHD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/ossec/ossec-hids/blob/master/etc/rules/sshd_rules.xml
        $string11_ssh_greyware_tool_keyword = /unknown\sor\sunsupported\skey\stype/ nocase ascii wide

    condition:
        any of them
}


rule sshx_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sshx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshx"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string1_sshx_greyware_tool_keyword = /\s\-\-bin\ssshx\-server/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string2_sshx_greyware_tool_keyword = /\ss3:\/\/sshx\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string3_sshx_greyware_tool_keyword = /\.vm\.sshx\.internal:8051/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string4_sshx_greyware_tool_keyword = /\/release\/sshx\-server/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string5_sshx_greyware_tool_keyword = /\/sshx\-server\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string6_sshx_greyware_tool_keyword = /\\sshx\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string7_sshx_greyware_tool_keyword = /cargo\sinstall\ssshx/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string8_sshx_greyware_tool_keyword = /ekzhang\/sshx/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string9_sshx_greyware_tool_keyword = /https:\/\/s3\.amazonaws\.com\/sshx\/sshx\-/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string10_sshx_greyware_tool_keyword = /https:\/\/sshx\.io\/get/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string11_sshx_greyware_tool_keyword = /https:\/\/sshx\.io\/s\// nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string12_sshx_greyware_tool_keyword = /sshx\-server\s\-\-listen/ nocase ascii wide
        // Description: Fast collaborative live terminal sharing over the web
        // Reference: https://github.com/ekzhang/sshx
        $string13_sshx_greyware_tool_keyword = /sshx\-server\-.{0,1000}\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}


rule sslip_io_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sslip.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sslip.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: sslip.io is a DNS server that maps specially-crafted DNS A records to IP addresses e.g. 127-0-0-1.sslip.io maps to 127.0.0.1
        // Reference: https://github.com/cunnie/sslip.io
        $string1_sslip_io_greyware_tool_keyword = /http.{0,1000}\.sslip\.io/ nocase ascii wide

    condition:
        any of them
}


rule sudo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sudo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Sudo Persistence via sudoers file
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_sudo_greyware_tool_keyword = /echo\s.{0,1000}\%sudo\s\sALL\=\(ALL\)\sNOPASSWD:\sALL.{0,1000}\s\>\>\s\/etc\/sudoers/ nocase ascii wide
        // Description: access sensitive files by abusing sudo permissions
        // Reference: N/A
        $string2_sudo_greyware_tool_keyword = /sudo\sapache2\s\-f\s\/etc\/shadow/ nocase ascii wide
        // Description: abusing LD_LIBRARY_PATH sudo option  to escalade privilege
        // Reference: N/A
        $string3_sudo_greyware_tool_keyword = /sudo\sLD_LIBRARY_PATH\=\.\sapache2/ nocase ascii wide
        // Description: abusinf LD_PREDLOAD option to escalade privilege
        // Reference: N/A
        $string4_sudo_greyware_tool_keyword = /sudo\sLD_PRELOAD\=\/tmp\/preload\.so\sfind/ nocase ascii wide

    condition:
        any of them
}


rule sudoers_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sudoers' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudoers"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: use SUDO without password
        // Reference: N/A
        $string1_sudoers_greyware_tool_keyword = /echo\s.{0,1000}\sALL\=\(ALL\)\sNOPASSWD:\sALL.{0,1000}\s\>\>\/etc\/sudoers/ nocase ascii wide
        // Description: use SUDO without password
        // Reference: N/A
        $string2_sudoers_greyware_tool_keyword = /echo\s.{0,1000}\sALL\=NOPASSWD:\s\/bin\/bash.{0,1000}\s\>\>\/etc\/sudoers/ nocase ascii wide

    condition:
        any of them
}


rule supershell_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string1_supershell_greyware_tool_keyword = /http:\/\/localhost:7681/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string2_supershell_greyware_tool_keyword = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7681\s/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string3_supershell_greyware_tool_keyword = /ttyd\s\-i\s0\.0\.0\.0\s\-p\s7682\s/ nocase ascii wide

    condition:
        any of them
}


rule Supremo_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Supremo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Supremo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string1_Supremo_greyware_tool_keyword = /\sstart\sSupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string2_Supremo_greyware_tool_keyword = /\sSupremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string3_Supremo_greyware_tool_keyword = /\/Supremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string4_Supremo_greyware_tool_keyword = /\\\\\.\\pipe\\Supremo/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string5_Supremo_greyware_tool_keyword = /\\Control\\SafeBoot\\Network\\SupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string6_Supremo_greyware_tool_keyword = /\\CurrentControlSet\\Services\\SupremoService/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string7_Supremo_greyware_tool_keyword = /\\Program\sFiles\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string8_Supremo_greyware_tool_keyword = /\\ProgramData\\SupremoRemoteDesktop/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string9_Supremo_greyware_tool_keyword = /\\SOFTWARE\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string10_Supremo_greyware_tool_keyword = /\\Software\\Supremo\\Printer\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string11_Supremo_greyware_tool_keyword = /\\SOFTWARE\\WOW6432Node\\Supremo\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string12_Supremo_greyware_tool_keyword = /\\Supremo\sRemote\sPrinter\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string13_Supremo_greyware_tool_keyword = /\\Supremo\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string14_Supremo_greyware_tool_keyword = /\\SUPREMO\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string15_Supremo_greyware_tool_keyword = /\\Supremo_Client_2/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string16_Supremo_greyware_tool_keyword = /\\Supremo_Helper_2/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string17_Supremo_greyware_tool_keyword = /\\Supremo_Service/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string18_Supremo_greyware_tool_keyword = /\\SupremoHelper\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string19_Supremo_greyware_tool_keyword = /\\SupremoRemoteDesktop\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string20_Supremo_greyware_tool_keyword = /\\Temp\\SupremoRemoteDesktop/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string21_Supremo_greyware_tool_keyword = /application\/x\-supremo/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string22_Supremo_greyware_tool_keyword = /HKCR\\supremo\\shell\\/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string23_Supremo_greyware_tool_keyword = /supremo\sremote\scontrol/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string24_Supremo_greyware_tool_keyword = /Supremo\.00\.Client\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string25_Supremo_greyware_tool_keyword = /Supremo\.00\.FileTransfer\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string26_Supremo_greyware_tool_keyword = /Supremo\.exe\s/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string27_Supremo_greyware_tool_keyword = /supremogw.{0,1000}\.nanosystems\.it/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string28_Supremo_greyware_tool_keyword = /supremohelper\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string29_Supremo_greyware_tool_keyword = /SupremoRemoteDesktop\\History\.txt/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string30_Supremo_greyware_tool_keyword = /SupremoService\.00\.Service\.log/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string31_Supremo_greyware_tool_keyword = /SupremoService\.exe/ nocase ascii wide
        // Description: Supremo - Remote access software
        // Reference: 	https://www.supremocontrol.com
        $string32_Supremo_greyware_tool_keyword = /SupremoSystem\.exe/ nocase ascii wide

    condition:
        any of them
}


rule Surf_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Surf VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Surf VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Surf_VPN_greyware_tool_keyword = /nhnfcgpcbfclhfafjlooihdfghaeinfc/ nocase ascii wide

    condition:
        any of them
}


rule sVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_sVPN_greyware_tool_keyword = /iocnglnmfkgfedpcemdflhkchokkfeii/ nocase ascii wide

    condition:
        any of them
}


rule sysctl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'sysctl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sysctl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Disable echo reply for icmpsh C2
        // Reference: https://github.com/bdamele/icmpsh
        $string1_sysctl_greyware_tool_keyword = /sysctl\s\-w\snet\.ipv4\.icmp_echo_ignore_all\=1/ nocase ascii wide

    condition:
        any of them
}


rule systemctl_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'systemctl' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "systemctl"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string1_systemctl_greyware_tool_keyword = /systemctl\sdisable\scbdaemon/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string2_systemctl_greyware_tool_keyword = /systemctl\sdisable\sfalcon\-sensor\.service/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string3_systemctl_greyware_tool_keyword = /systemctl\sstop\scbdaemon/ nocase ascii wide
        // Description: Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes* deleting Registry keys so that tools do not start at run time* or other methods to interfere with security tools scanning or reporting information.
        // Reference: https://attack.mitre.org/techniques/T1562/001/
        $string4_systemctl_greyware_tool_keyword = /systemctl\sstop\sfalcon\-sensor\.service/ nocase ascii wide

    condition:
        any of them
}


rule tacticalrmm_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tacticalrmm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tacticalrmm"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string1_tacticalrmm_greyware_tool_keyword = /\srmm\-installer\.ps1/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string2_tacticalrmm_greyware_tool_keyword = /\stacticalrmm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string3_tacticalrmm_greyware_tool_keyword = /\/amidaware\/rmmagent\/releases\/download\// nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string4_tacticalrmm_greyware_tool_keyword = /\/nats\-rmm\.conf/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string5_tacticalrmm_greyware_tool_keyword = /\/rmm\/api\/tacticalrmm\// nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string6_tacticalrmm_greyware_tool_keyword = /\/rmm\-installer\.ps1/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string7_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\.log/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string8_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\-v.{0,1000}\-.{0,1000}\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string9_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\-v.{0,1000}\-linux\-arm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string10_tacticalrmm_greyware_tool_keyword = /\/tacticalagent\-v.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string11_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string12_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\.git/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string13_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\/master\/install\.sh/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string14_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\/releases\/latest/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string15_tacticalrmm_greyware_tool_keyword = /\/tacticalrmm\-web\.git/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string16_tacticalrmm_greyware_tool_keyword = /\\InventoryApplicationFile\\tacticalagent\-v2/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string17_tacticalrmm_greyware_tool_keyword = /\\Program\sFiles\\TacticalAgent\\/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string18_tacticalrmm_greyware_tool_keyword = /\\ProgramData\\TacticalRMM\\/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string19_tacticalrmm_greyware_tool_keyword = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string20_tacticalrmm_greyware_tool_keyword = /\\rmm\-client\-site\-server\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string21_tacticalrmm_greyware_tool_keyword = /\\rmm\-installer\.ps1/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string22_tacticalrmm_greyware_tool_keyword = /\\tacticalagent\-v.{0,1000}\-linux\-arm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string23_tacticalrmm_greyware_tool_keyword = /\\tacticalagent\-v.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string24_tacticalrmm_greyware_tool_keyword = /\\tacticalrmm\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string25_tacticalrmm_greyware_tool_keyword = /\\tacticalrmm\\/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string26_tacticalrmm_greyware_tool_keyword = /amidaware\/tacticalrmm/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string27_tacticalrmm_greyware_tool_keyword = /https:\/\/.{0,1000}\.tacticalrmm\.com\// nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string28_tacticalrmm_greyware_tool_keyword = /net\sstop\stacticalrmm/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string29_tacticalrmm_greyware_tool_keyword = /RMM\.WebRemote\.exe/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string30_tacticalrmm_greyware_tool_keyword = /SOFTWARE\\TacticalRMM/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string31_tacticalrmm_greyware_tool_keyword = /su\s\-\stactical/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string32_tacticalrmm_greyware_tool_keyword = /sudo\s\-s\s\/bin\/bash\stactical/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string33_tacticalrmm_greyware_tool_keyword = /systemctl\s.{0,1000}\srmm\.service/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string34_tacticalrmm_greyware_tool_keyword = /Tactical\sRMM\sAgent/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string35_tacticalrmm_greyware_tool_keyword = /tacticalrmm\.utils/ nocase ascii wide
        // Description: A remote monitoring & management tool
        // Reference: https://github.com/amidaware/tacticalrmm
        $string36_tacticalrmm_greyware_tool_keyword = /tacticalrmm\-develop/ nocase ascii wide

    condition:
        any of them
}


rule tailscale_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tailscale' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tailscale"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string1_tailscale_greyware_tool_keyword = /\sinstall\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string2_tailscale_greyware_tool_keyword = /\snet\-vpn\/tailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string3_tailscale_greyware_tool_keyword = /\stailscale\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string4_tailscale_greyware_tool_keyword = /\stailscale\-archive\-keyring/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string5_tailscale_greyware_tool_keyword = /\.tailscale\-keyring\.list/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string6_tailscale_greyware_tool_keyword = /\/cmd\/tailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string7_tailscale_greyware_tool_keyword = /\/sources\.list\.d\/tailscale\.list/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string8_tailscale_greyware_tool_keyword = /\/tailscale\supdate/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string9_tailscale_greyware_tool_keyword = /\/tailscale\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string10_tailscale_greyware_tool_keyword = /\/tailscale\/cli\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string11_tailscale_greyware_tool_keyword = /\/tailscale\/client\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string12_tailscale_greyware_tool_keyword = /\/tailscale\/clientupdate\/.{0,1000}\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string13_tailscale_greyware_tool_keyword = /\/tailscale:unstable/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string14_tailscale_greyware_tool_keyword = /\/tailscale_.{0,1000}_.{0,1000}\.deb/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string15_tailscale_greyware_tool_keyword = /\/tailscale_.{0,1000}_.{0,1000}\.tgz/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string16_tailscale_greyware_tool_keyword = /\/tailscaled\.defaults/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string17_tailscale_greyware_tool_keyword = /\/tailscaled\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string18_tailscale_greyware_tool_keyword = /\/tailscaled\.sock/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string19_tailscale_greyware_tool_keyword = /\/tailscale\-setup\-.{0,1000}\-.{0,1000}\.msi/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string20_tailscale_greyware_tool_keyword = /\/tailscale\-setup\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string21_tailscale_greyware_tool_keyword = /\/test_tailscale\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string22_tailscale_greyware_tool_keyword = /\\\\\.\\pipe\\tailscale\-test/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string23_tailscale_greyware_tool_keyword = /\\cmd\\tailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string24_tailscale_greyware_tool_keyword = /\\tailscale\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string25_tailscale_greyware_tool_keyword = /\\tailscale\\cli\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string26_tailscale_greyware_tool_keyword = /\\tailscale\\client\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string27_tailscale_greyware_tool_keyword = /\\tailscale\\clientupdate\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string28_tailscale_greyware_tool_keyword = /\\tailscale\\cmd\\/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string29_tailscale_greyware_tool_keyword = /\\tailscale_.{0,1000}_.{0,1000}\.deb/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string30_tailscale_greyware_tool_keyword = /\\tailscale_.{0,1000}_.{0,1000}\.tgz/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string31_tailscale_greyware_tool_keyword = /\\tailscaled\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string32_tailscale_greyware_tool_keyword = /\\tailscale\-setup\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string33_tailscale_greyware_tool_keyword = /\\test_tailscale\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string34_tailscale_greyware_tool_keyword = /\<h1\>Hello\sfrom\sTailscale\<\/h1\>/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string35_tailscale_greyware_tool_keyword = /apk\sadd\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string36_tailscale_greyware_tool_keyword = /cmd\/tailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string37_tailscale_greyware_tool_keyword = /connected\svia\stailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string38_tailscale_greyware_tool_keyword = /EnableTailscaleDNSSettings/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string39_tailscale_greyware_tool_keyword = /EnableTailscaleSubnets/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string40_tailscale_greyware_tool_keyword = /github\.com\/tailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string41_tailscale_greyware_tool_keyword = /http:\/\/127\.0\.0\.1:4000/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string42_tailscale_greyware_tool_keyword = /http:\/\/local\-tailscaled\.sock/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string43_tailscale_greyware_tool_keyword = /https:\/\/api\.tailscale\.com\/api\/v2\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string44_tailscale_greyware_tool_keyword = /https:\/\/apps\.apple\.com\/us\/app\/tailscale\/id/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string45_tailscale_greyware_tool_keyword = /https:\/\/login\.tailscale\.com\/admin\/settings\/keys/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string46_tailscale_greyware_tool_keyword = /https:\/\/tailscale\.com\/s\/resolvconf\-overwrite/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string47_tailscale_greyware_tool_keyword = /install\s\-y\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string48_tailscale_greyware_tool_keyword = /linuxfw\.TailscaleSubnetRouteMark/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string49_tailscale_greyware_tool_keyword = /local\-tailscaled\.sock/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string50_tailscale_greyware_tool_keyword = /login\.tailscale\.com/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string51_tailscale_greyware_tool_keyword = /pacman\s\-S\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string52_tailscale_greyware_tool_keyword = /pkgctl\-Tailscale\.service/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string53_tailscale_greyware_tool_keyword = /pkgs\.tailscale\.com\/.{0,1000}\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string54_tailscale_greyware_tool_keyword = /rc\-update\sadd\stailscale/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string55_tailscale_greyware_tool_keyword = /resolv\.pre\-tailscale\-backup\.conf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string56_tailscale_greyware_tool_keyword = /resolv\.tailscale\.conf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string57_tailscale_greyware_tool_keyword = /service\stailscaled\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string58_tailscale_greyware_tool_keyword = /Serving\sTailscale\sweb\sclient\son\shttp:\/\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string59_tailscale_greyware_tool_keyword = /Starting\stailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string60_tailscale_greyware_tool_keyword = /sudo\stailscale\sup/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string61_tailscale_greyware_tool_keyword = /systemctl\senable\s\-\-now\stailscaled/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string62_tailscale_greyware_tool_keyword = /tailscale\sip\s\-4/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string63_tailscale_greyware_tool_keyword = /Tailscale\sis\snot\srunning/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string64_tailscale_greyware_tool_keyword = /tailscale\sping\s\-/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string65_tailscale_greyware_tool_keyword = /tailscale\sserve\s\-/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string66_tailscale_greyware_tool_keyword = /tailscale\sset\s\-\-auto\-update/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string67_tailscale_greyware_tool_keyword = /Tailscale\sSSH\sis\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string68_tailscale_greyware_tool_keyword = /tailscale\sup\s\-\-login\-server\=/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string69_tailscale_greyware_tool_keyword = /Tailscale\swas\salready\sstopped/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string70_tailscale_greyware_tool_keyword = /tailscale\.com\/install\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string71_tailscale_greyware_tool_keyword = /tailscale\.com\/logger\.Logf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string72_tailscale_greyware_tool_keyword = /tailscale\.exe\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string73_tailscale_greyware_tool_keyword = /tailscale\/go\/releases\/download\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string74_tailscale_greyware_tool_keyword = /tailscale\/net\/dns\// nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string75_tailscale_greyware_tool_keyword = /tailscale\/tailscale\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string76_tailscale_greyware_tool_keyword = /tailscale\\net\\dns/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string77_tailscale_greyware_tool_keyword = /tailscale\\scripts\\installer\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string78_tailscale_greyware_tool_keyword = /tailscale\\tailscale\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string79_tailscale_greyware_tool_keyword = /Tailscaled\sexited/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string80_tailscale_greyware_tool_keyword = /tailscaled\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string81_tailscale_greyware_tool_keyword = /tailscaled\.log/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string82_tailscale_greyware_tool_keyword = /tailscaled\.openrc/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string83_tailscale_greyware_tool_keyword = /tailscaled\.sh/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string84_tailscale_greyware_tool_keyword = /tailscaled\.stdout\.log/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string85_tailscale_greyware_tool_keyword = /tailscaled_notwindows\.go/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string86_tailscale_greyware_tool_keyword = /tailscale\-ipn\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string87_tailscale_greyware_tool_keyword = /tailscale\-ipn\.log\.conf/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string88_tailscale_greyware_tool_keyword = /tailscale\-setup\-.{0,1000}\.exe\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string89_tailscale_greyware_tool_keyword = /tailscale\-setup\-full\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string90_tailscale_greyware_tool_keyword = /Updating\sTailscale\sfrom\s/ nocase ascii wide
        // Description: Tailscale connects your team's devices and development environments for easy access to remote resources.
        // Reference: https://github.com/tailscale/tailscale
        $string91_tailscale_greyware_tool_keyword = /yum\.repos\.d\/tailscale\.repo/ nocase ascii wide

    condition:
        any of them
}


rule takeown_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'takeown' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "takeown"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1_takeown_greyware_tool_keyword = /takeown\s\/f\s\"C:\\windows\\system32\\config\\SAM\"/ nocase ascii wide
        // Description: Spartacus DLL/COM Hijacking Toolkit
        // Reference: https://www.pavel.gr/blog/neutralising-amsi-system-wide-as-an-admin
        $string2_takeown_greyware_tool_keyword = /takeown\s\/f\sC:\\Windows\\System32\\amsi\.dll\s\/a/ nocase ascii wide

    condition:
        any of them
}


rule tasklist_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tasklist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tasklist"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1_tasklist_greyware_tool_keyword = /tasklist\s\/svc\s\|\sfindstr\s\/i\s\"vmtoolsd\.exe\"/ nocase ascii wide

    condition:
        any of them
}


rule tcpdump_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tcpdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tcpdump"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A powerful command-line packet analyzer.and libpcap. a portable C/C++ library for network traffic capture
        // Reference: http://www.tcpdump.org/
        $string1_tcpdump_greyware_tool_keyword = /tcpdump\s/ nocase ascii wide

    condition:
        any of them
}


rule teamviewer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'teamviewer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "teamviewer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string1_teamviewer_greyware_tool_keyword = /\.router\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string2_teamviewer_greyware_tool_keyword = /\/Create\s\/TN\sTVInstallRestore\s\/TR\s/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string3_teamviewer_greyware_tool_keyword = /\\AppData\\Roaming\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string4_teamviewer_greyware_tool_keyword = /\\CurrentControlSet\\Services\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string5_teamviewer_greyware_tool_keyword = /\\Program\sFiles\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string6_teamviewer_greyware_tool_keyword = /\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string7_teamviewer_greyware_tool_keyword = /\\Software\\TeamViewer\\Temp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string8_teamviewer_greyware_tool_keyword = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string9_teamviewer_greyware_tool_keyword = /\\TeamViewer\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string10_teamviewer_greyware_tool_keyword = /\\TeamViewer\\Connections\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string11_teamviewer_greyware_tool_keyword = /\\TeamViewer\\Connections_incoming\.txt/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string12_teamviewer_greyware_tool_keyword = /\\TeamViewer_\.ex/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string13_teamviewer_greyware_tool_keyword = /\\teamviewer_note\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string14_teamviewer_greyware_tool_keyword = /\\TeamViewerSession\\shell\\open/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string15_teamviewer_greyware_tool_keyword = /\\TeamViewerTermsOfUseAccepted/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string16_teamviewer_greyware_tool_keyword = /\\TV15Install\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string17_teamviewer_greyware_tool_keyword = /\\TVExtractTemp\\TeamViewer_Resource_/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string18_teamviewer_greyware_tool_keyword = /\\TVExtractTemp\\tvfiles\.7z/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string19_teamviewer_greyware_tool_keyword = /\\TvGetVersion\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string20_teamviewer_greyware_tool_keyword = /\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string21_teamviewer_greyware_tool_keyword = /\\TVWebRTC\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string22_teamviewer_greyware_tool_keyword = /\\Users\\Public\\Desktop\\TVTest\.tmp/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string23_teamviewer_greyware_tool_keyword = /\\Windows\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string24_teamviewer_greyware_tool_keyword = /AppData\\Local\\Temp\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string25_teamviewer_greyware_tool_keyword = /AppData\\Roaming\\Microsoft\\Windows\\SendTo\\TeamViewer\.lnk/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string26_teamviewer_greyware_tool_keyword = /client\.teamviewer\.com/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string27_teamviewer_greyware_tool_keyword = /download\.teamviewer\.com\.cdn\.cloudflare\.net/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string28_teamviewer_greyware_tool_keyword = /HKLM\\SOFTWARE\\TeamViewer/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string29_teamviewer_greyware_tool_keyword = /MRU\\RemoteSupport\\127\.0\.0\.1\.tvc/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string30_teamviewer_greyware_tool_keyword = /TeamViewer\sVPN\sAdapter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string31_teamviewer_greyware_tool_keyword = /TEAMVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string32_teamviewer_greyware_tool_keyword = /TeamViewer\\tv_w32\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string33_teamviewer_greyware_tool_keyword = /TeamViewer\\tv_x64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string34_teamviewer_greyware_tool_keyword = /TeamViewer\\tv_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string35_teamviewer_greyware_tool_keyword = /TeamViewer\\TVNetwork\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string36_teamviewer_greyware_tool_keyword = /TEAMVIEWER_\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string37_teamviewer_greyware_tool_keyword = /TeamViewer_Desktop\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string38_teamviewer_greyware_tool_keyword = /TEAMVIEWER_DESKTOP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string39_teamviewer_greyware_tool_keyword = /TeamViewer_Hooks\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string40_teamviewer_greyware_tool_keyword = /TeamViewer_Service\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string41_teamviewer_greyware_tool_keyword = /TEAMVIEWER_SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string42_teamviewer_greyware_tool_keyword = /TeamViewer_Setup_x64\.exe/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string43_teamviewer_greyware_tool_keyword = /TEAMVIEWER_SETUP_X64\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string44_teamviewer_greyware_tool_keyword = /TeamViewer_VirtualDeviceDriver/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string45_teamviewer_greyware_tool_keyword = /TeamViewer_XPSDriverFilter/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string46_teamviewer_greyware_tool_keyword = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string47_teamviewer_greyware_tool_keyword = /TeamViewer15_Logfile\.log/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string48_teamviewer_greyware_tool_keyword = /TeamViewerMeetingAddIn\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string49_teamviewer_greyware_tool_keyword = /TeamViewerMeetingAddinShim\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string50_teamviewer_greyware_tool_keyword = /TeamViewerMeetingAddinShim64\.dll/ nocase ascii wide
        // Description: TeamViewer Remote is software for remote assistance - control and access to computers and other terminals - abused by attackers
        // Reference: https://www.teamviewer.com/
        $string51_teamviewer_greyware_tool_keyword = /teamviewervpn\.sys/ nocase ascii wide

    condition:
        any of them
}


rule TelegramRAT_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TelegramRAT' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TelegramRAT"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Cross Platform Telegram based RAT that communicates via telegram to evade network restrictions
        // Reference: https://github.com/machine1337/TelegramRAT
        $string1_TelegramRAT_greyware_tool_keyword = /https:\/\/api\.telegram\.org\/bot.{0,1000}\/sendMessage/ nocase ascii wide

    condition:
        any of them
}


rule telnet_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'telnet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telnet"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious shell commands used in various Equation Group scripts and tools
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/lnx_apt_equationgroup_lnx.yml
        $string1_telnet_greyware_tool_keyword = /\&\&\stelnet\s.{0,1000}\s2\>\&1\s\<\/dev\/console/ nocase ascii wide
        // Description: telnet reverse shell 
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string2_telnet_greyware_tool_keyword = /telnet\s.{0,1000}\s\|\s\/bin\/bash\s\|\stelnet\s/ nocase ascii wide

    condition:
        any of them
}


rule temp_sh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'temp.sh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "temp.sh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_temp_sh_greyware_tool_keyword = /https:\/\/temp\.sh\/.{0,1000}\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2_temp_sh_greyware_tool_keyword = /https:\/\/temp\.sh\/upload/ nocase ascii wide

    condition:
        any of them
}


rule tempsend_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tempsend.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tempsend.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_tempsend_com_greyware_tool_keyword = /https:\/\/tempsend\.com\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2_tempsend_com_greyware_tool_keyword = /https:\/\/tempsend\.com\/send/ nocase ascii wide

    condition:
        any of them
}


rule textbin_net_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'textbin.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "textbin.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: textbin.net raw access content - abused by malwares to retrieve payloads
        // Reference: textbin.net
        $string1_textbin_net_greyware_tool_keyword = /https:\/\/textbin\.net\/raw\// nocase ascii wide

    condition:
        any of them
}


rule Thunder_Proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Thunder Proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Thunder Proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Thunder_Proxy_greyware_tool_keyword = /knmmpciebaoojcpjjoeonlcjacjopcpf/ nocase ascii wide

    condition:
        any of them
}


rule tir_blanc_holiseum_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tir_blanc_holiseum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tir_blanc_holiseum"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ransomware simulation
        // Reference: https://www.holiseum.com/services/auditer/tir-a-blanc-ransomware
        $string1_tir_blanc_holiseum_greyware_tool_keyword = /\\tir_blanc_holiseum\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Ransomware simulation
        // Reference: https://www.holiseum.com/services/auditer/tir-a-blanc-ransomware
        $string2_tir_blanc_holiseum_greyware_tool_keyword = /kindloader\.exe.{0,1000}\s\-\-extract\skindlocker/ nocase ascii wide

    condition:
        any of them
}


rule tmpfiles_org_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tmpfiles.org' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpfiles.org"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: download of an executable files from tmpfiles.org often used by ransomware groups
        // Reference: N/A
        $string1_tmpfiles_org_greyware_tool_keyword = /https:\/\/tmpfiles\.org\/dl\/.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}


rule tmpwatch_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'tmpwatch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpwatch"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string1_tmpwatch_greyware_tool_keyword = /chmod\s4777\s\/tmp\/\.scsi\/dev\/bin\/gsh/ nocase ascii wide
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string2_tmpwatch_greyware_tool_keyword = /chown\sroot:root\s\/tmp\/\.scsi\/dev\/bin\// nocase ascii wide
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string3_tmpwatch_greyware_tool_keyword = /echo\s.{0,1000}bailing\.\stry\sa\sdifferent\sname\\/ nocase ascii wide
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string4_tmpwatch_greyware_tool_keyword = /if\s\[\s\-f\s\/tmp\/tmpwatch\s\]\s.{0,1000}\sthen/ nocase ascii wide

    condition:
        any of them
}


rule Touch_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Touch VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Touch VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Touch_VPN_greyware_tool_keyword = /bihmplhobchoageeokmgbdihknkjbknd/ nocase ascii wide

    condition:
        any of them
}


rule touch_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'touch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "touch"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string1_touch_greyware_tool_keyword = /touch\s\-a/ nocase ascii wide
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string2_touch_greyware_tool_keyword = /touch\s\-m/ nocase ascii wide
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string3_touch_greyware_tool_keyword = /touch\s\-r\s/ nocase ascii wide
        // Description: Timestomping is an anti-forensics technique which is used to modify the timestamps of a file* often to mimic files that are in the same folder.
        // Reference: https://github.com/elastic/detection-rules/blob/main/rules/linux/defense_evasion_timestomp_touch.toml
        $string4_touch_greyware_tool_keyword = /touch\s\-t\s/ nocase ascii wide

    condition:
        any of them
}


rule transfer_sh_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'transfer.sh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfer.sh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_transfer_sh_greyware_tool_keyword = /https:\/\/transfer\.sh/ nocase ascii wide

    condition:
        any of them
}


rule transfert_my_files_com_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'transfert-my-files.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "transfert-my-files.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string1_transfert_my_files_com_greyware_tool_keyword = /https:\/\/transfert\-my\-files\.com\/files\// nocase ascii wide
        // Description: Interesting observation on the file-sharing platform preferences derived from the negotiations chats with LockBit victims
        // Reference: https://twitter.com/mthcht/status/1660953897622544384
        $string2_transfert_my_files_com_greyware_tool_keyword = /https:\/\/transfert\-my\-files\.com\/inc\/upload\.php/ nocase ascii wide

    condition:
        any of them
}


rule translate_goog_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'translate.goog' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "translate.goog"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: accessing github through google translate (evasion) false positive risk
        // Reference: https://*-com.translate.goog/*
        $string1_translate_goog_greyware_tool_keyword = /https:\/\/github\-com\.translate\.goog\// nocase ascii wide

    condition:
        any of them
}


rule Trellonet_Trellonet_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Trellonet Trellonet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Trellonet Trellonet"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Trellonet_Trellonet_greyware_tool_keyword = /njpmifchgidinihmijhcfpbdmglecdlb/ nocase ascii wide

    condition:
        any of them
}


rule TunnelBear_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TunnelBear VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TunnelBear VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_TunnelBear_VPN_greyware_tool_keyword = /omdakjcmkglenbhjadbccaookpfjihpa/ nocase ascii wide

    condition:
        any of them
}


rule Tunnello_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Tunnello VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tunnello VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Tunnello_VPN_greyware_tool_keyword = /hoapmlpnmpaehilehggglehfdlnoegck/ nocase ascii wide

    condition:
        any of them
}


rule Turbo_VPN_for_PC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Turbo VPN for PC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Turbo VPN for PC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Turbo_VPN_for_PC_greyware_tool_keyword = /jliodmnojccaloajphkingdnpljdhdok/ nocase ascii wide

    condition:
        any of them
}


rule Ultrareach_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Ultrareach VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ultrareach VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Ultrareach_VPN_greyware_tool_keyword = /mjnbclmflcpookeapghfhapeffmpodij/ nocase ascii wide

    condition:
        any of them
}


rule UltraVNC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'UltraVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UltraVNC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string1_UltraVNC_greyware_tool_keyword = /\sstart\suvnc_service/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string2_UltraVNC_greyware_tool_keyword = /\sstop\suvnc_service/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string3_UltraVNC_greyware_tool_keyword = /\sultravnc\.ini\s/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string4_UltraVNC_greyware_tool_keyword = /\svnc\.ini\s/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string5_UltraVNC_greyware_tool_keyword = /\"publisher\":\"uvnc\sbvba/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string6_UltraVNC_greyware_tool_keyword = /\/downloads\/ultravnc\.html/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string7_UltraVNC_greyware_tool_keyword = /\\127\.0\.0\.1\-5900\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string8_UltraVNC_greyware_tool_keyword = /\\AppData\\Roaming\\.{0,1000}\-5900\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string9_UltraVNC_greyware_tool_keyword = /\\AppData\\Roaming\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string10_UltraVNC_greyware_tool_keyword = /\\createpassword\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string11_UltraVNC_greyware_tool_keyword = /\\CurrentVersion\\Uninstall\\Ultravnc2_is1\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string12_UltraVNC_greyware_tool_keyword = /\\InventoryApplicationFile\\ultravnc_/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string13_UltraVNC_greyware_tool_keyword = /\\options\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string14_UltraVNC_greyware_tool_keyword = /\\Services\\EventLog\\Application\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string15_UltraVNC_greyware_tool_keyword = /\\SOFTWARE\\ORL\\VNCHooks\\Application_Prefs\\WinVNC/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string16_UltraVNC_greyware_tool_keyword = /\\ultravnc\.cer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string17_UltraVNC_greyware_tool_keyword = /\\UltraVNC\.ini/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string18_UltraVNC_greyware_tool_keyword = /\\uvnc\sbvba\\UltraVNC\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string19_UltraVNC_greyware_tool_keyword = /\\uvnc_launch\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string20_UltraVNC_greyware_tool_keyword = /\\uvnc_settings\.ex/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string21_UltraVNC_greyware_tool_keyword = /\\uvnc_settings\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string22_UltraVNC_greyware_tool_keyword = /\\uvnckeyboardhelper\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string23_UltraVNC_greyware_tool_keyword = /\\vncviewer\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string24_UltraVNC_greyware_tool_keyword = /\\winvnc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string25_UltraVNC_greyware_tool_keyword = /\\winvncsc\.exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string26_UltraVNC_greyware_tool_keyword = /\\winwvc\.exe	/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string27_UltraVNC_greyware_tool_keyword = /bvba_UltraVNC_.{0,1000}_exe/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string28_UltraVNC_greyware_tool_keyword = /certutil\.exe.{0,1000}\s\-addstore\s\"TrustedPublisher\".{0,1000}ultravnc\.cer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string29_UltraVNC_greyware_tool_keyword = /\'Company\'\>UltraVNC\<\/Data\>/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string30_UltraVNC_greyware_tool_keyword = /\'Description\'\>VNC\sserver\<\/Data\>/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string31_UltraVNC_greyware_tool_keyword = /firewall\sadd\sallowedprogram\s.{0,1000}vncviewer\.exe.{0,1000}\sENABLE\sALL/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string32_UltraVNC_greyware_tool_keyword = /firewall\sadd\sallowedprogram\s.{0,1000}winvnc\.exe.{0,1000}\sENABLE\sALL/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string33_UltraVNC_greyware_tool_keyword = /firewall\sadd\sportopening\sTCP\s5800\svnc5800/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string34_UltraVNC_greyware_tool_keyword = /firewall\sadd\sportopening\sTCP\s5900\svnc5900/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string35_UltraVNC_greyware_tool_keyword = /HKCR\\\.vnc/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string36_UltraVNC_greyware_tool_keyword = /Program\sFiles\s\(x86\)\\uvnc\sbvba\\/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string37_UltraVNC_greyware_tool_keyword = /UltraVNC\sLauncher\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string38_UltraVNC_greyware_tool_keyword = /ultravnc\smslogonacl/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string39_UltraVNC_greyware_tool_keyword = /UltraVNC\sRepeater\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string40_UltraVNC_greyware_tool_keyword = /UltraVNC\sServer\sSettings\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string41_UltraVNC_greyware_tool_keyword = /UltraVNC\sServer\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string42_UltraVNC_greyware_tool_keyword = /ultravnc\stestauth/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string43_UltraVNC_greyware_tool_keyword = /UltraVNC\sViewer\.lnk/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string44_UltraVNC_greyware_tool_keyword = /UltraVNC_.{0,1000}_X86_Setup/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string45_UltraVNC_greyware_tool_keyword = /ULTRAVNC_1.{0,1000}_X86_SETUP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string46_UltraVNC_greyware_tool_keyword = /ultravnc_repeater/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string47_UltraVNC_greyware_tool_keyword = /ultravnc_server/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string48_UltraVNC_greyware_tool_keyword = /ultravnc_viewer/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string49_UltraVNC_greyware_tool_keyword = /VNCviewer\sConfig\sFile/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string50_UltraVNC_greyware_tool_keyword = /VncViewer\.Config/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string51_UltraVNC_greyware_tool_keyword = /VNCVIEWER\.EXE\-.{0,1000}\.pf/ nocase ascii wide
        // Description: UltraVNC remote access software usage
        // Reference: https://uvnc.com/downloads/ultravnc.html
        $string52_UltraVNC_greyware_tool_keyword = /WinVNC\.exe/ nocase ascii wide

    condition:
        any of them
}


rule Unblock_Websites_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Unblock Websites' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Unblock Websites"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Unblock_Websites_greyware_tool_keyword = /gbmdmipapolaohpinhblmcnpmmlgfgje/ nocase ascii wide

    condition:
        any of them
}


rule Unlimited_VPN__and__Proxy_by_ibVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Unlimited VPN & Proxy by ibVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Unlimited VPN & Proxy by ibVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Unlimited_VPN__and__Proxy_by_ibVPN_greyware_tool_keyword = /higioemojdadgdbhbbbkfbebbdlfjbip/ nocase ascii wide

    condition:
        any of them
}


rule unset_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unset' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unset"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disable history logging
        // Reference: https://github.com/hak5/omg-payloads/tree/master/payloads/library/credentials/OMGLogger
        $string1_unset_greyware_tool_keyword = /unset\sHISTFILE\s\&\&\sHISTSIZE\=0\s\&\&\srm\s\-f\s\$HISTFILE_unset_greyware_tool_keyword\s\&\&\sunset\sHISTFILE/ nocase ascii wide
        // Description: linux commands abused by attackers
        // Reference: N/A
        $string2_unset_greyware_tool_keyword = /unset\sHISTFILE/ nocase ascii wide

    condition:
        any of them
}


rule unshadow_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'unshadow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "unshadow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1_unshadow_greyware_tool_keyword = /unshadow\spasswd\sshadow\s\>\s/ nocase ascii wide

    condition:
        any of them
}


rule updog_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'updog' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "updog"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string1_updog_greyware_tool_keyword = /\/updog\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string2_updog_greyware_tool_keyword = /\/updog\.git/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string3_updog_greyware_tool_keyword = /\/updog\/archive\/updog\-/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string4_updog_greyware_tool_keyword = /\\updog\-master\\/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string5_updog_greyware_tool_keyword = /pip.{0,1000}\sinstall\supdog/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string6_updog_greyware_tool_keyword = /sc0tfree\/updog/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string7_updog_greyware_tool_keyword = /updog\s\-\-/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string8_updog_greyware_tool_keyword = /updog\s\-d\s\// nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string9_updog_greyware_tool_keyword = /updog\s\-p\s/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string10_updog_greyware_tool_keyword = /updog\-master\.zip/ nocase ascii wide

    condition:
        any of them
}


rule Upnet_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Upnet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Upnet"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Upnet_greyware_tool_keyword = /bniikohfmajhdcffljgfeiklcbgffppl/ nocase ascii wide

    condition:
        any of them
}


rule Urban_Free_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Urban Free VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Urban Free VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Urban_Free_VPN_greyware_tool_keyword = /eppiocemhmnlbhjplcgkofciiegomcon/ nocase ascii wide

    condition:
        any of them
}


rule Urban_Shield_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Urban Shield' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Urban Shield"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Urban_Shield_greyware_tool_keyword = /almalgbpmcfpdaopimbdchdliminoign/ nocase ascii wide

    condition:
        any of them
}


rule utorrent_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'utorrent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "utorrent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string1_utorrent_greyware_tool_keyword = /\\uTorrent\\/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string2_utorrent_greyware_tool_keyword = /\\utweb\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string3_utorrent_greyware_tool_keyword = /AppData\\Roaming\\uTorrent/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string4_utorrent_greyware_tool_keyword = /uTorrent\s\(1\)\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string5_utorrent_greyware_tool_keyword = /uTorrent\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string6_utorrent_greyware_tool_keyword = /utorrent_installer\.exe/ nocase ascii wide
        // Description: popular BitTorrent client used for downloading files over the BitTorrent network. a peer-to-peer file sharing protocol. Can be used for collection and exfiltration. Not something we want to see installed in a enterprise network
        // Reference: https[://]www[.]utorrent[.]com/intl/fr/
        $string7_utorrent_greyware_tool_keyword = /utweb_installer\.exe/ nocase ascii wide

    condition:
        any of them
}


rule uVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'uVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "uVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_uVPN_greyware_tool_keyword = /lejgfmmlngaigdmmikblappdafcmkndb/ nocase ascii wide

    condition:
        any of them
}


rule Veee_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Veee' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Veee"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Veee_greyware_tool_keyword = /bnijmipndnicefcdbhgcjoognndbgkep/ nocase ascii wide

    condition:
        any of them
}


rule VirtualShield_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VirtualShield VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VirtualShield VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VirtualShield_VPN_greyware_tool_keyword = /aojlhgbkmkahabcmcpifbolnoichfeep/ nocase ascii wide

    condition:
        any of them
}


rule vncviewer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vncviewer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vncviewer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string1_vncviewer_greyware_tool_keyword = /vncviewer\s.{0,1000}\..{0,1000}:5901/ nocase ascii wide

    condition:
        any of them
}


rule VPN_Free_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Free' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Free"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_Free_greyware_tool_keyword = /gjknjjomckknofjidppipffbpoekiipm/ nocase ascii wide

    condition:
        any of them
}


rule VPN_Master_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Master' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Master"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_Master_greyware_tool_keyword = /akeehkgglkmpapdnanoochpfmeghfdln/ nocase ascii wide

    condition:
        any of them
}


rule VPN_Professional_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Professional' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Professional"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_Professional_greyware_tool_keyword = /foiopecknacmiihiocgdjgbjokkpkohc/ nocase ascii wide

    condition:
        any of them
}


rule VPN_PROXY_MASTER_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN PROXY MASTER' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN PROXY MASTER"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_PROXY_MASTER_greyware_tool_keyword = /lnfdmdhmfbimhhpaeocncdlhiodoblbd/ nocase ascii wide

    condition:
        any of them
}


rule VPN_Unlimited_Free_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN Unlimited Free' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN Unlimited Free"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_Unlimited_Free_greyware_tool_keyword = /mpcaainmfjjigeicjnlkdfajbioopjko/ nocase ascii wide

    condition:
        any of them
}


rule VPN_free_pro_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN-free.pro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN-free.pro"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_free_pro_greyware_tool_keyword = /bibjcjfmgapbfoljiojpipaooddpkpai/ nocase ascii wide

    condition:
        any of them
}


rule VPN_AC_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPN.AC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPN.AC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPN_AC_greyware_tool_keyword = /kcndmbbelllkmioekdagahekgimemejo/ nocase ascii wide

    condition:
        any of them
}


rule VPNMatic_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'VPNMatic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VPNMatic"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_VPNMatic_greyware_tool_keyword = /bkkgdjpomdnfemhhkalfkogckjdkcjkg/ nocase ascii wide

    condition:
        any of them
}


rule vscode_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vscode' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vscode"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string1_vscode_greyware_tool_keyword = /aue\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string2_vscode_greyware_tool_keyword = /aue\-data\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: Starts a reverse connection over global.rel.tunnels.api.visualstudio.com via websockets
        // Reference: https://badoption.eu/blog/2023/01/31/code_c2.html
        $string3_vscode_greyware_tool_keyword = /code\.exe\stunnel\s\-\-accept\-server\-license\-terms\s\-\-name\s/ nocase ascii wide
        // Description: Starts a reverse connection over global.rel.tunnels.api.visualstudio.com via websockets
        // Reference: https://badoption.eu/blog/2023/01/31/code_c2.html
        $string4_vscode_greyware_tool_keyword = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide
        // Description: built-in port forwarding. This feature allows you to share locally running services over the internet to other people and devices.
        // Reference: https://twitter.com/code/status/1699869087071899669
        $string5_vscode_greyware_tool_keyword = /global\.rel\.tunnels\.api\.visualstudio\.com/ nocase ascii wide

    condition:
        any of them
}


rule vsftpd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vsftpd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vsftpd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string1_vsftpd_greyware_tool_keyword = /Bad\sHTTP\sverb\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string2_vsftpd_greyware_tool_keyword = /bug:\spid\sactive\sin\sptrace_sandbox_free/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string3_vsftpd_greyware_tool_keyword = /Connection\srefused:\stcp_wrappers\sdenial\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string4_vsftpd_greyware_tool_keyword = /Connection\srefused:\stoo\smany\ssessions\sfor\sthis\saddress\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string5_vsftpd_greyware_tool_keyword = /Could\snot\sset\sfile\smodification\stime\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string6_vsftpd_greyware_tool_keyword = /couldn\'t\shandle\ssandbox\sevent/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string7_vsftpd_greyware_tool_keyword = /Input\sline\stoo\slong\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string8_vsftpd_greyware_tool_keyword = /pasv\sand\sport\sboth\sactive/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string9_vsftpd_greyware_tool_keyword = /poor\sbuffer\saccounting\sin\sstr_netfd_alloc/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string10_vsftpd_greyware_tool_keyword = /port\sand\spasv\sboth\sactive/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string11_vsftpd_greyware_tool_keyword = /PTRACE_SETOPTIONS\sfailure/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string12_vsftpd_greyware_tool_keyword = /syscall\s.{0,1000}\sout\sof\sbounds/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string13_vsftpd_greyware_tool_keyword = /syscall\snot\spermitted:/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string14_vsftpd_greyware_tool_keyword = /syscall\svalidate\sfailed:/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string15_vsftpd_greyware_tool_keyword = /Transfer\sdone\s\(but\sfailed\sto\sopen\sdirectory\)\./ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string16_vsftpd_greyware_tool_keyword = /vsf_sysutil_read_loop/ nocase ascii wide
        // Description: Detects suspicious VSFTPD error messages that indicate a fatal or suspicious error that could be caused by exploiting attempts
        // Reference: https://github.com/dagwieers/vsftpd/
        $string17_vsftpd_greyware_tool_keyword = /weird\sstatus:/ nocase ascii wide

    condition:
        any of them
}


rule vssadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'vssadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vssadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string1_vssadmin_greyware_tool_keyword = /\.exe\sdelete\sshadows/ nocase ascii wide
        // Description: the command is used to create a new Volume Shadow Copy for a specific volume which can be utilized by an attacker to collect data from the local system
        // Reference: N/A
        $string2_vssadmin_greyware_tool_keyword = /vssadmin\screate\sshadow\s\/for\=C:/ nocase ascii wide
        // Description: the actor creating a Shadow Copy and then extracting a copy of the ntds.dit file from it.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3_vssadmin_greyware_tool_keyword = /vssadmin\screate\sshadow\s\/for\=C:.{0,1000}\s\\Temp\\.{0,1000}\.tmp/ nocase ascii wide
        // Description: inhibiting recovery by deleting backup and recovery data to prevent system recovery after an attack
        // Reference: N/A
        $string4_vssadmin_greyware_tool_keyword = /vssadmin\sdelete\sshadows/ nocase ascii wide
        // Description: List shadow copies using vssadmin
        // Reference: N/A
        $string5_vssadmin_greyware_tool_keyword = /vssadmin\slist\sshadows/ nocase ascii wide
        // Description: Deletes all Volume Shadow Copies from the system quietly (without prompts).
        // Reference: N/A
        $string6_vssadmin_greyware_tool_keyword = /vssadmin.{0,1000}\sDelete\sShadows\s\/All\s\/Quiet/ nocase ascii wide

    condition:
        any of them
}


rule Wachee_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Wachee VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Wachee VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Wachee_VPN_greyware_tool_keyword = /bhnhkdgoefpmekcgnccpnhjfdgicfebm/ nocase ascii wide

    condition:
        any of them
}


rule wbadmin_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wbadmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wbadmin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: hinder recovery efforts with wbadmin
        // Reference: N/A
        $string1_wbadmin_greyware_tool_keyword = /wbadmin\sdelete\sbackup/ nocase ascii wide
        // Description: Wbadmin allows administrators to manage and automate backup and recovery operations in Windows systems. Adversaries may abuse wbadmin to manipulate backups and restore points as part of their evasion tactics. This can include deleting backup files. disabling backup tasks. or tampering with backup configurations to hinder recovery efforts and potentially erase traces of their malicious activities. By interfering with backups. adversaries can make it more challenging for defenders to restore systems and detect their presence.
        // Reference: N/A
        $string2_wbadmin_greyware_tool_keyword = /wbadmin\sDELETE\sSYSTEMSTATEBACKUP\s\-deleteOldest/ nocase ascii wide
        // Description: Wbadmin allows administrators to manage and automate backup and recovery operations in Windows systems. Adversaries may abuse wbadmin to manipulate backups and restore points as part of their evasion tactics. This can include deleting backup files. disabling backup tasks. or tampering with backup configurations to hinder recovery efforts and potentially erase traces of their malicious activities. By interfering with backups. adversaries can make it more challenging for defenders to restore systems and detect their presence.
        // Reference: N/A
        $string3_wbadmin_greyware_tool_keyword = /wbadmin\sDELETE\sSYSTEMSTATEBACKUP/ nocase ascii wide

    condition:
        any of them
}


rule westwind_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'westwind' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "westwind"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_westwind_greyware_tool_keyword = /gbfgfbopcfokdpkdigfmoeaajfmpkbnh/ nocase ascii wide

    condition:
        any of them
}


rule wetransfer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wetransfer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wetransfer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: WeTransfer is a popular file sharing service often used by malicious actors for phishing campaigns due to its legitimate reputation and widespread use even within some enterprises to share files
        // Reference: https://twitter.com/mthcht/status/1658853848323182597
        $string1_wetransfer_greyware_tool_keyword = /https:\/\/we\.tl\/t\-/ nocase ascii wide
        // Description: WeTransfer is a popular file-sharing service often used by malicious actors for phishing campaigns due to its legitimate reputation and widespread use even within some enterprises to share files
        // Reference: https://twitter.com/mthcht/status/1658853848323182597
        $string2_wetransfer_greyware_tool_keyword = /https:\/\/wetransfer\.com\/api\/v4\/transfers\// nocase ascii wide
        // Description: WeTransfer is a popular file-sharing service often used by malicious actors for phishing campaigns due to its legitimate reputation and widespread use even within some enterprises to share files
        // Reference: https://twitter.com/mthcht/status/1658853848323182597
        $string3_wetransfer_greyware_tool_keyword = /https:\/\/wetransfer\.com\/downloads\// nocase ascii wide

    condition:
        any of them
}


rule WeVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WeVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WeVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_WeVPN_greyware_tool_keyword = /ehbhfpfdkmhcpaehaooegfdflljcnfec/ nocase ascii wide

    condition:
        any of them
}


rule wevtutil_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wevtutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wevtutil"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string1_wevtutil_greyware_tool_keyword = /cmd.{0,1000}\swevtutil\.exe\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string2_wevtutil_greyware_tool_keyword = /wevtutil\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string3_wevtutil_greyware_tool_keyword = /wevtutil\sclear\-log/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string4_wevtutil_greyware_tool_keyword = /wevtutil\.exe\scl\s/ nocase ascii wide
        // Description: adversaries can delete specific event logs or clear their contents. erasing potentially valuable information that could aid in detection. incident response. or forensic investigations. This tactic aims to hinder forensic analysis efforts and make it more challenging for defenders to reconstruct the timeline of events or identify malicious activities.
        // Reference: N/A
        $string5_wevtutil_greyware_tool_keyword = /wevtutil\.exe\sclear\-log/ nocase ascii wide
        // Description: disable a specific eventlog
        // Reference: N/A
        $string6_wevtutil_greyware_tool_keyword = /wevtutil\.exe\ssl\s.{0,1000}\s\/e:false/ nocase ascii wide

    condition:
        any of them
}


rule where_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'where' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "where"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: threat actors searched for Active Directory related DLLs in directories
        // Reference: https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware/
        $string1_where_greyware_tool_keyword = /\swhere\s\/r\sC:\\Windows\\WinSxS\\\s.{0,1000}Microsoft\.ActiveDirectory\.Management\.dll/ nocase ascii wide

    condition:
        any of them
}


rule whoami_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'whoami' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "whoami"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string1_whoami_greyware_tool_keyword = /whoami\s\/all/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string2_whoami_greyware_tool_keyword = /whoami\s\/domain/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string3_whoami_greyware_tool_keyword = /whoami\s\/groups/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4_whoami_greyware_tool_keyword = /whoami\s\/priv/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string5_whoami_greyware_tool_keyword = /whoami/ nocase ascii wide
        // Description: whoami is a legitimate command used to identify the current user executing the command in a terminal or command prompt.whoami can be used to gather information about the current user's privileges. credentials. and account name. which can then be used for lateral movement. privilege escalation. or targeted attacks within the compromised network.
        // Reference: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.yaml
        $string6_whoami_greyware_tool_keyword = /whoami\.exe.{0,1000}\s\/groups/ nocase ascii wide

    condition:
        any of them
}


rule Whoer_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Whoer VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Whoer VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Whoer_VPN_greyware_tool_keyword = /cgojmfochfikphincbhokimmmjenhhgk/ nocase ascii wide

    condition:
        any of them
}


rule WindmillVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WindmillVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WindmillVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_WindmillVPN_greyware_tool_keyword = /ggackgngljinccllcmbgnpgpllcjepgc/ nocase ascii wide

    condition:
        any of them
}


rule Windscribe_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Windscribe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Windscribe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_Windscribe_greyware_tool_keyword = /hnmpcagpplmpfojmgmnngilcnanddlhb/ nocase ascii wide

    condition:
        any of them
}


rule winrs_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'winrs' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "winrs"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: WinRS for Lateral Movement
        // Reference: N/A
        $string1_winrs_greyware_tool_keyword = /winrs\s\-r:.{0,1000}whoami/ nocase ascii wide

    condition:
        any of them
}


rule wireshark_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wireshark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wireshark"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string1_wireshark_greyware_tool_keyword = /dl\.wireshark\.org/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string2_wireshark_greyware_tool_keyword = /dumpcap\s\-/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string3_wireshark_greyware_tool_keyword = /install\stshark/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string4_wireshark_greyware_tool_keyword = /libwireshark16/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string5_wireshark_greyware_tool_keyword = /libwireshark\-data/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string6_wireshark_greyware_tool_keyword = /libwireshark\-dev/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string7_wireshark_greyware_tool_keyword = /libwiretap13/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string8_wireshark_greyware_tool_keyword = /\-\-no\-promiscuous\-mode/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string9_wireshark_greyware_tool_keyword = /sharkd\s\-a\stcp:/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string10_wireshark_greyware_tool_keyword = /tshark\s.{0,1000}\-i\s/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string11_wireshark_greyware_tool_keyword = /tshark\s\-f\s/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string12_wireshark_greyware_tool_keyword = /tshark\s\-Q/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string13_wireshark_greyware_tool_keyword = /tshark\s\-r\s/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string14_wireshark_greyware_tool_keyword = /tshark.{0,1000}\.deb/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string15_wireshark_greyware_tool_keyword = /Wireshark/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string16_wireshark_greyware_tool_keyword = /wireshark.{0,1000}\.deb/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string17_wireshark_greyware_tool_keyword = /Wireshark.{0,1000}\.dmg/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string18_wireshark_greyware_tool_keyword = /wireshark\-.{0,1000}\.tar\.xz/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string19_wireshark_greyware_tool_keyword = /wireshark\-common/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string20_wireshark_greyware_tool_keyword = /wireshark\-dev/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string21_wireshark_greyware_tool_keyword = /wireshark\-gtk/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string22_wireshark_greyware_tool_keyword = /WiresharkPortable64/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string23_wireshark_greyware_tool_keyword = /wireshark\-qt/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string24_wireshark_greyware_tool_keyword = /Wireshark\-win.{0,1000}\.exe/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string25_wireshark_greyware_tool_keyword = /capinfos\s\-/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string26_wireshark_greyware_tool_keyword = /captype\s\-/ nocase ascii wide
        // Description: Wireshark is a network protocol analyzer.
        // Reference: https://www.wireshark.org/
        $string27_wireshark_greyware_tool_keyword = /rawshark\s\-/ nocase ascii wide

    condition:
        any of them
}


rule wmic_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'wmic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmic"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Threat Actors ran the following command to download and execute a PowerShell payload
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string1_wmic_greyware_tool_keyword = /\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\spowershell\.exe\s\-nop\s\-w\shidden\s\-c\s.{0,1000}IEX\s\(\(new\-object\snet\.webclient\)\.downloadstring\(\'https:\/\// nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string2_wmic_greyware_tool_keyword = /\.exe\sshadowcopy\sdelete/ nocase ascii wide
        // Description: The NTDS.dit file is the heart of Active Directory including user accounts If it's found in the Temp directory it could indicate that an attacker has copied the file here in an attempt to extract sensitive information.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string3_wmic_greyware_tool_keyword = /\\Temp\\.{0,1000}\\ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in the Temp directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string4_wmic_greyware_tool_keyword = /\\Temp\\.{0,1000}\\ntds\.jfm/ nocase ascii wide
        // Description: this file shouldn't be found in the Users\Public directory. Its presence could be a sign of an ongoing or past attack.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string5_wmic_greyware_tool_keyword = /\\Users\\Public\\.{0,1000}ntds\.dit/ nocase ascii wide
        // Description: Like the ntds.dit file it should not normally be found in this directory.
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6_wmic_greyware_tool_keyword = /\\Users\\Public\\.{0,1000}ntds\.jfm/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string7_wmic_greyware_tool_keyword = /ac\si\sntds.{0,1000}\\\\127\.0\.0\.1\\ADMIN\$\\/ nocase ascii wide
        // Description: gather information about Windows OS version and licensing on the hosts
        // Reference: https://thedfirreport.com/2023/05/22/icedid-macro-ends-in-nokoyawa-ransomware/
        $string8_wmic_greyware_tool_keyword = /cmd\.exe\s\/C\swmic\s\/node:.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\sos\sget\scaption/ nocase ascii wide
        // Description: Enable WinRM remotely with wmic
        // Reference: N/A
        $string9_wmic_greyware_tool_keyword = /process\scall\screate\s\"powershell\senable\-psremoting\s\-force\"/ nocase ascii wide
        // Description: WMIC suspicious transfer 
        // Reference: N/A
        $string10_wmic_greyware_tool_keyword = /start\swmic\s\/node:\@C:\\.{0,1000}\.txt\s\/user:.{0,1000}\/password:.{0,1000}\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\sbitsadmin\s\/transfer\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string11_wmic_greyware_tool_keyword = /Win32_Shadowcopy\s\|\sForEach\-Object\s{\$__wmic_greyware_tool_keyword\.Delete\(\)\;/ nocase ascii wide
        // Description: Lateral Movement with wmic
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string12_wmic_greyware_tool_keyword = /wmic\s\/.{0,1000}\s\/user:administrator\sprocess\scall\screate\s.{0,1000}cmd\.exe\s\/c\s/ nocase ascii wide
        // Description: Execute file hosted over SMB on remote system with specified credential
        // Reference: N/A
        $string13_wmic_greyware_tool_keyword = /wmic\s\/node:.{0,1000}\s\/user:.{0,1000}\s\/password:.{0,1000}\sprocess\scall\screate\s\"\\\\.{0,1000}\\.{0,1000}\.exe/ nocase ascii wide
        // Description: Remotely start RDP with wmic
        // Reference: N/A
        $string14_wmic_greyware_tool_keyword = /wmic\s\/node:.{0,1000}\spath\sWin32_TerminalServiceSetting\swhere\sAllowTSConnections\=\"0\"\scall\sSetAllowTSConnections\s\"1\"/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string15_wmic_greyware_tool_keyword = /wmic\s\/node:.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}computersystem\sget\susername/ nocase ascii wide
        // Description: get the currently logged user with wmic
        // Reference: N/A
        $string16_wmic_greyware_tool_keyword = /wmic\s\/node:.{0,1000}localhost.{0,1000}computersystem\sget\susername/ nocase ascii wide
        // Description: get domain name with wmic
        // Reference: N/A
        $string17_wmic_greyware_tool_keyword = /wmic\scomputersystem\sget\sdomain/ nocase ascii wide
        // Description: The actor has executed WMIC commands [T1047] to create a copy of the ntds.dit file and SYSTEM registry hive using ntdsutil.exe
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string18_wmic_greyware_tool_keyword = /wmic\sprocess\scall\screate.{0,1000}ntdsutil\s.{0,1000}ac\si\sntds.{0,1000}\sifm.{0,1000}create\sfull/ nocase ascii wide
        // Description: list all running processes and their command lines on a Windows system
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string19_wmic_greyware_tool_keyword = /wmic\sprocess\sget\scommandline\s\-all/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string20_wmic_greyware_tool_keyword = /wmic\sservice\sbrief/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string21_wmic_greyware_tool_keyword = /wmic\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string22_wmic_greyware_tool_keyword = /wmic\sshadowcopy\sdelete/ nocase ascii wide
        // Description: User Enumeration
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string23_wmic_greyware_tool_keyword = /wmic\suseraccount\sget\s\/ALL\s\/format:csv/ nocase ascii wide
        // Description: wmic discovery commands abused by attackers
        // Reference: N/A
        $string24_wmic_greyware_tool_keyword = /wmic\svolume\slist\sbrief/ nocase ascii wide
        // Description: list AV products with wmic
        // Reference: N/A
        $string25_wmic_greyware_tool_keyword = /wmic.{0,1000}\/Namespace:\\\\root\\SecurityCenter2\sPath\sAntiVirusProduct\sGet\sdisplayName/ nocase ascii wide
        // Description: Execute a .EXE file stored as an Alternate Data Stream (ADS)
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Anti-Forensics.md
        $string26_wmic_greyware_tool_keyword = /wmic\.exe\sprocess\scall\screate\s.{0,1000}\.txt:.{0,1000}\.exe/ nocase ascii wide
        // Description: call cmd.exe with wmic
        // Reference: N/A
        $string27_wmic_greyware_tool_keyword = /wmic\.exe\sprocess\scall\screate\s.{0,1000}cmd\s\/c\s/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string28_wmic_greyware_tool_keyword = /wmic\.exe\sSHADOWCOPY\s\/nointeractive/ nocase ascii wide
        // Description: VSS is a feature in Windows that allows for the creation of snapshots of a volume capturing its state at a specific point in time. Adversaries may abuse the wmic shadowcopy command to interact with these shadow copies for defense evasion purposes.
        // Reference: N/A
        $string29_wmic_greyware_tool_keyword = /wmic\.exe\sshadowcopy\sdelete/ nocase ascii wide

    condition:
        any of them
}


rule WorkingVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'WorkingVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WorkingVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_WorkingVPN_greyware_tool_keyword = /mhngpdlhojliikfknhfaglpnddniijfh/ nocase ascii wide

    condition:
        any of them
}


rule xcopy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xcopy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xcopy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: command abused by attackers - exfiltraiton to remote host with xcopy
        // Reference: N/A
        $string1_xcopy_greyware_tool_keyword = /xcopy\sc:\\.{0,1000}\s\\\\.{0,1000}\\c\$/ nocase ascii wide

    condition:
        any of them
}


rule xmrig_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xmrig' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xmrig"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string1_xmrig_greyware_tool_keyword = /\s\-\-coin\s.{0,1000}\-\-nicehash\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string2_xmrig_greyware_tool_keyword = /\s\-\-coin\=monero/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string3_xmrig_greyware_tool_keyword = /\s\-\-nicehash\s.{0,1000}\-\-coin\s/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string4_xmrig_greyware_tool_keyword = /\/xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string5_xmrig_greyware_tool_keyword = /\/xmrig\.exe/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string6_xmrig_greyware_tool_keyword = /\/xmrig\.git/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string7_xmrig_greyware_tool_keyword = /\\WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string8_xmrig_greyware_tool_keyword = /\\xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string9_xmrig_greyware_tool_keyword = /\\xmrig\.exe/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string10_xmrig_greyware_tool_keyword = /\\xmrig\-6\.20\.0/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string11_xmrig_greyware_tool_keyword = /\\xmrig\-master/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string12_xmrig_greyware_tool_keyword = /08384f3f05ad85b2aa935dbd2e46a053cb0001b28bbe593dde2a8c4b822c2a7d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string13_xmrig_greyware_tool_keyword = /3b5cbf0dddc3ef7e3af7d783baef315bf47be6ce11ff83455a2165befe6711f5/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string14_xmrig_greyware_tool_keyword = /4fe9647d6a8bf4790df0277283f9874385e0cd05f3008406ca5624aba8d78924/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string15_xmrig_greyware_tool_keyword = /5575c76987333427f74263e090910eae45817f0ede6b452d645fd5f9951210c9/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string16_xmrig_greyware_tool_keyword = /5a6e7d5c10789763b0b06442dbc7f723f8ea9aec1402abedf439c6801a8d86f2/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string17_xmrig_greyware_tool_keyword = /99e3e313b62bb8b55e2637fc14a78adb6f33632a3c722486416252e2630cfdf6/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string18_xmrig_greyware_tool_keyword = /dd7fef5e3594eb18dd676e550e128d4b64cc5a469ff6954a677dc414265db468/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string19_xmrig_greyware_tool_keyword = /donate\.v2\.xmrig\.com:3333/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string20_xmrig_greyware_tool_keyword = /e1ff2208b3786cac801ffb470b9475fbb3ced74eb503bfde7aa7f22af113989d/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string21_xmrig_greyware_tool_keyword = /ff6e67d725ee64b4607dc6490a706dc9234c708cff814477de52d3beb781c6a1/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string22_xmrig_greyware_tool_keyword = /github.{0,1000}\/xmrig\/xmrig/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string23_xmrig_greyware_tool_keyword = /gpg_keys\/xmrig\.asc/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string24_xmrig_greyware_tool_keyword = /solo_mine_example\.cmd/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string25_xmrig_greyware_tool_keyword = /src\/xmrig\.cpp/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string26_xmrig_greyware_tool_keyword = /src\\xmrig\.cpp/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string27_xmrig_greyware_tool_keyword = /WinRing0.{0,1000}WinRing0x64\.sys/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string28_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-bionic\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string29_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-focal\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string30_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-freebsd\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string31_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-gcc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string32_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-linux\-static\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string33_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-linux\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string34_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-macos\-arm64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string35_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-macos\-x64\.tar\.gz/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string36_xmrig_greyware_tool_keyword = /xmrig\-.{0,1000}\-msvc\-win64\.zip/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string37_xmrig_greyware_tool_keyword = /xmrig\.exe\s\-/ nocase ascii wide
        // Description: CPU/GPU cryptominer often used by attackers on compromised machines
        // Reference: https://github.com/xmrig/xmrig/
        $string38_xmrig_greyware_tool_keyword = /xmrpool\.eu:3333/ nocase ascii wide

    condition:
        any of them
}


rule xxd_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'xxd' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xxd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ICMP Tunneling One Liner
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1_xxd_greyware_tool_keyword = /xxd\s\-p\s\-c\s4\s\/.{0,1000}\s\|\swhile\sread\sline.{0,1000}\sdo\sping\s\-c\s1\s\-p\s/ nocase ascii wide

    condition:
        any of them
}


rule ZenMate_VPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'ZenMate VPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZenMate VPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1_ZenMate_VPN_greyware_tool_keyword = /fdcgdnkidjaadafnichfpabhfomcebme/ nocase ascii wide

    condition:
        any of them
}


rule index_allocation_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '$index_allocation_index_allocation_greyware_tool_keyword' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "$index_allocation_index_allocation_greyware_tool_keyword"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: creation of hidden folders (and file) via ...$.......::$index_allocation_index_allocation_greyware_tool_keyword
        // Reference: https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
        $string1_index_allocation_greyware_tool_keyword = /\.\.\.::\$index_allocation_index_allocation_greyware_tool_keyword/ nocase ascii wide
        // Description: creation of hidden folders (and file) via ...$.......::$index_allocation_index_allocation_greyware_tool_keyword
        // Reference: https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
        $string2_index_allocation_greyware_tool_keyword = /cd\s.{0,1000}\.::\$index_allocation_index_allocation_greyware_tool_keyword/ nocase ascii wide
        // Description: creation of hidden folders (and file) via ...$.......::$index_allocation_index_allocation_greyware_tool_keyword
        // Reference: https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
        $string3_index_allocation_greyware_tool_keyword = /md\s.{0,1000}\.::\$index_allocation_index_allocation_greyware_tool_keyword/ nocase ascii wide

    condition:
        any of them
}


rule _1clickVPN_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '1clickVPN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "1clickVPN"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: External VPN usage within coporate network
        // Reference: https://raw.githubusercontent.com/SigmaHQ/sigma/43277f26fc1c81fc98fc79147b711189e901b757/rules/windows/registry/registry_set/registry_set_chrome_extension.yml
        $string1__1clickVPN_greyware_tool_keyword = /fcfhplploccackoneaefokcmbjfbkenj/ nocase ascii wide

    condition:
        any of them
}


rule _3proxy_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '3proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string1__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,1000}\.deb/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string2__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string3__3proxy_greyware_tool_keyword = /\/3proxy\-.{0,1000}\.zip/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string4__3proxy_greyware_tool_keyword = /\/3proxy\.exe/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string5__3proxy_greyware_tool_keyword = /\/3proxy\.git/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string6__3proxy_greyware_tool_keyword = /\/3proxy\.log/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string7__3proxy_greyware_tool_keyword = /\/etc\/3proxy\/conf/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string8__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,1000}\.deb/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string9__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string10__3proxy_greyware_tool_keyword = /\\3proxy\-.{0,1000}\.zip/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string11__3proxy_greyware_tool_keyword = /\\3proxy\.cfg/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string12__3proxy_greyware_tool_keyword = /\\3proxy\.exe/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string13__3proxy_greyware_tool_keyword = /\\3proxy\.key/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string14__3proxy_greyware_tool_keyword = /\\3proxy\.log/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string15__3proxy_greyware_tool_keyword = /\\bin\\3proxy/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string16__3proxy_greyware_tool_keyword = /128s3proxy\.key\"/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string17__3proxy_greyware_tool_keyword = /3proxy\s\-\-install/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string18__3proxy_greyware_tool_keyword = /3proxy\s\-\-remove/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string19__3proxy_greyware_tool_keyword = /3proxy\stiny\sproxy\sserver/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string20__3proxy_greyware_tool_keyword = /3proxy\sWindows\sAuthentication\splugin/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string21__3proxy_greyware_tool_keyword = /3proxy\.exe\s\-\-/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string22__3proxy_greyware_tool_keyword = /3proxy\.service/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string23__3proxy_greyware_tool_keyword = /3proxy\/3proxy/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string24__3proxy_greyware_tool_keyword = /3proxy\@3proxy\.org/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string25__3proxy_greyware_tool_keyword = /add3proxyuser\.sh/ nocase ascii wide

    condition:
        any of them
}


rule __greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "_"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: attempt to bypass security controls or execute commands from an unexpected location
        // Reference: https://twitter.com/malwrhunterteam/status/1737220172220620854/photo/1
        $string1___greyware_tool_keyword = /\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\\.\.\\Windows\\System32\\cmd\.exe/ nocase ascii wide
        // Description: generic suspicious keyword keygen.exe observed in multiple cracked software often packed with malwares
        // Reference: N/A
        $string2___greyware_tool_keyword = /\/keygen\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string3___greyware_tool_keyword = /\\1\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string4___greyware_tool_keyword = /\\1\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string5___greyware_tool_keyword = /\\1\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string6___greyware_tool_keyword = /\\2\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string7___greyware_tool_keyword = /\\2\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string8___greyware_tool_keyword = /\\2\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string9___greyware_tool_keyword = /\\3\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string10___greyware_tool_keyword = /\\3\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string11___greyware_tool_keyword = /\\3\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string12___greyware_tool_keyword = /\\4\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string13___greyware_tool_keyword = /\\4\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string14___greyware_tool_keyword = /\\4\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string15___greyware_tool_keyword = /\\5\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string16___greyware_tool_keyword = /\\5\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string17___greyware_tool_keyword = /\\5\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string18___greyware_tool_keyword = /\\6\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string19___greyware_tool_keyword = /\\6\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string20___greyware_tool_keyword = /\\6\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string21___greyware_tool_keyword = /\\7\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string22___greyware_tool_keyword = /\\7\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string23___greyware_tool_keyword = /\\7\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string24___greyware_tool_keyword = /\\8\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string25___greyware_tool_keyword = /\\8\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string26___greyware_tool_keyword = /\\8\.exe/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string27___greyware_tool_keyword = /\\9\.bat/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string28___greyware_tool_keyword = /\\9\.dll/ nocase ascii wide
        // Description: Suspicious file names - One caracter executables often used by threat actors (warning false positives)
        // Reference: N/A
        $string29___greyware_tool_keyword = /\\9\.exe/ nocase ascii wide
        // Description: generic suspicious keyword keygen.exe observed in multiple cracked software often packed with malwares
        // Reference: N/A
        $string30___greyware_tool_keyword = /\\keygen\.exe/ nocase ascii wide

    condition:
        any of them
}


