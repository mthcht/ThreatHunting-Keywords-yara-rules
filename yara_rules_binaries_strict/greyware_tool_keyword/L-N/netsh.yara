rule netsh
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Opens port 3389 for RDP inbound access through the firewall
        // Reference: N/A
        $string1 = /\sadvfirewall\sfirewall\sadd\srule\s.{0,100}\sdir\=in\sprotocol\=tcp\slocalport\=3389\saction\=allow/ nocase ascii wide
        // Description: display saved Wi-Fi profiles on a Windows system
        // Reference: N/A
        $string2 = /\\netsh\.exe\\"\swlan\sshow\sprofiles/ nocase ascii wide
        // Description: the loop exhausts available IP addresses on the network by assigning static IP addresses, which depletes the pool of IPs that the DHCP server can assign to legitimate devices
        // Reference: N/A
        $string3 = /for\s\/L\s\%i\sin\s\(2\,1\,254\)\sdo\s\(netsh\sinterface\sip\sset\saddress\slocal\sstatic/ nocase ascii wide
        // Description: allow rdp incoming connection - used by ransomware groups
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = "netsh advfirewall firewall add rule name=\"allow RDP\" dir=in protocol=TCP localport=3389 action=allow" nocase ascii wide
        // Description: gathering information about network configurations
        // Reference: N/A
        $string5 = "netsh advfirewall firewall show rule name=all" nocase ascii wide
        // Description: script to dismantle complete windows defender protection and even bypass tamper protection  - Disable Windows-Defender Permanently.
        // Reference: https://github.com/swagkarna/Defeat-Defender-V1.2.0
        $string6 = "netsh advfirewall set allprofiles state off" nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string7 = "NetSh Advfirewall set allprofiles state off" nocase ascii wide
        // Description: adding a executable in user appdata folder to the allowed programs
        // Reference: https://tria.ge/231006-ydmxjsfe5s/behavioral1/analog?proc=66
        $string8 = /netsh\sfirewall\sadd\sallowedprogram\s\\"C\:\\Users\\.{0,100}\\AppData\\.{0,100}\.exe\\"\s\\".{0,100}\.exe\\"\sENABLE/ nocase ascii wide
        // Description: delete a item from firewall allowedprogram Whitelist
        // Reference: N/A
        $string9 = "netsh firewall delete allowedprogram " nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string10 = "netsh firewall set opmode disable" nocase ascii wide
        // Description: Enumeration with netsh
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string11 = "netsh firewall show all" nocase ascii wide
        // Description: show all firewall rules config
        // Reference: N/A
        $string12 = "netsh firewall show config" nocase ascii wide
        // Description: Enumeration with netsh
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string13 = "netsh interface firewall show all" nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string14 = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,100}\sconnectaddress\=/ nocase ascii wide
        // Description: The actor has used the following commands to enable port forwarding [T1090] on the host
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string15 = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,100}listenaddress\=.{0,100}\slistenport\=.{0,100}connectaddress\=.{0,100}connectport/ nocase ascii wide
        // Description: attempt to remove port proxy configurations
        // Reference: https://media.defense.gov/2024/Feb/07/2003389936/-1/-1/0/JOINT-GUIDANCE-IDENTIFYING-AND-MITIGATING-LOTL.PDF
        $string16 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenaddress\=0\.0\.0\.0\slistenport\=/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string17 = "netsh interface portproxy delete v4tov4 listenport=" nocase ascii wide
        // Description: display all current TCP port redirections configured on the system
        // Reference: N/A
        $string18 = "netsh interface portproxy show all" nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string19 = "netsh interface portproxy show v4tov4" nocase ascii wide
        // Description: Enumeration with netsh
        // Reference: https://medium.com/detect-fyi/playbook-hunting-chinese-apt-379a6b950492
        $string20 = "netsh portproxy show v4tov4" nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string21 = /netsh\swlan\sshow\sprofiles\s.{0,100}key\=clear/ nocase ascii wide
        // Description: Adds a new rule to the Windows firewall that allows incoming RDP traffic.
        // Reference: https://www.cisa.gov/sites/default/files/2023-05/aa23-136a_stopransomware_bianlian_ransomware_group_1.pdf
        $string22 = /netsh\.exe\sadvfirewall\sfirewall\sadd\srule\s\\"name\=allow\sRemoteDesktop\\"\sdir\=in\s.{0,100}\slocalport\=.{0,100}\saction\=allow/ nocase ascii wide
        // Description: Enables the pre-existing Windows firewall rule group named Remote Desktop. This rule group allows incoming RDP traffic.
        // Reference: https://www.cisa.gov/sites/default/files/2023-05/aa23-136a_stopransomware_bianlian_ransomware_group_1.pdf
        $string23 = /netsh\.exe\sadvfirewall\sfirewall\sset\srule\s\\"group\=remote\sdesktop\\"\snew\senable\=Yes/ nocase ascii wide
        // Description: capturing a network trace with netsh
        // Reference: N/A
        $string24 = /netsh\.exe\strace\sstart\smaxSize\=1\sfileMode\=single\scapture\=yes\straceFile\=.{0,100}\\TEMP.{0,100}\.etl/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string25 = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
        // Description: display all current TCP port redirections configured on the system
        // Reference: N/A
        $string26 = /netsh\.exe.{0,100}\sinterface\sportproxy\sshow\sall/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
