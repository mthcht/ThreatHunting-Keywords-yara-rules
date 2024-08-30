rule netsh
{
    meta:
        description = "Detection patterns for the tool 'netsh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netsh"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: gathering information about network configurations
        // Reference: N/A
        $string1 = /netsh\sadvfirewall\sfirewall\sshow\srule\sname\=all/ nocase ascii wide
        // Description: script to dismantle complete windows defender protection and even bypass tamper protection  - Disable Windows-Defender Permanently.
        // Reference: https://github.com/swagkarna/Defeat-Defender-V1.2.0
        $string2 = /netsh\sadvfirewall\sset\sallprofiles\sstate\soff/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string3 = /NetSh\sAdvfirewall\sset\sallprofiles\sstate\soff/ nocase ascii wide
        // Description: adding a executable in user appdata folder to the allowed programs
        // Reference: https://tria.ge/231006-ydmxjsfe5s/behavioral1/analog?proc=66
        $string4 = /netsh\sfirewall\sadd\sallowedprogram\s\"C\:\\Users\\.{0,1000}\\AppData\\.{0,1000}\.exe\"\s\".{0,1000}\.exe\"\sENABLE/ nocase ascii wide
        // Description: delete a item from firewall allowedprogram Whitelist
        // Reference: N/A
        $string5 = /netsh\sfirewall\sdelete\sallowedprogram\s/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string6 = /netsh\sfirewall\sset\sopmode\sdisable/ nocase ascii wide
        // Description: show all firewall rules config
        // Reference: N/A
        $string7 = /netsh\sfirewall\sshow\sconfig/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string8 = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,1000}\sconnectaddress\=/ nocase ascii wide
        // Description: The actor has used the following commands to enable port forwarding [T1090] on the host
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string9 = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,1000}listenaddress\=.{0,1000}\slistenport\=.{0,1000}connectaddress\=.{0,1000}connectport/ nocase ascii wide
        // Description: attempt to remove port proxy configurations
        // Reference: https://media.defense.gov/2024/Feb/07/2003389936/-1/-1/0/JOINT-GUIDANCE-IDENTIFYING-AND-MITIGATING-LOTL.PDF
        $string10 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenaddress\=0\.0\.0\.0\slistenport\=/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string11 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenport\=/ nocase ascii wide
        // Description: display all current TCP port redirections configured on the system
        // Reference: N/A
        $string12 = /netsh\sinterface\sportproxy\sshow\sall/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string13 = /netsh\sinterface\sportproxy\sshow\sv4tov4/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string14 = /netsh\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
        // Description: Adds a new rule to the Windows firewall that allows incoming RDP traffic.
        // Reference: https://www.cisa.gov/sites/default/files/2023-05/aa23-136a_stopransomware_bianlian_ransomware_group_1.pdf
        $string15 = /netsh\.exe\sadvfirewall\sfirewall\sadd\srule\s\"name\=allow\sRemoteDesktop\"\sdir\=in\s.{0,1000}\slocalport\=.{0,1000}\saction\=allow/ nocase ascii wide
        // Description: Enables the pre-existing Windows firewall rule group named Remote Desktop. This rule group allows incoming RDP traffic.
        // Reference: https://www.cisa.gov/sites/default/files/2023-05/aa23-136a_stopransomware_bianlian_ransomware_group_1.pdf
        $string16 = /netsh\.exe\sadvfirewall\sfirewall\sset\srule\s\"group\=remote\sdesktop\"\snew\senable\=Yes/ nocase ascii wide
        // Description: capturing a network trace with netsh
        // Reference: N/A
        $string17 = /netsh\.exe\strace\sstart\smaxSize\=1\sfileMode\=single\scapture\=yes\straceFile\=.{0,1000}\\TEMP.{0,1000}\.etl/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string18 = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
        // Description: display all current TCP port redirections configured on the system
        // Reference: N/A
        $string19 = /netsh\.exe.{0,1000}\sinterface\sportproxy\sshow\sall/ nocase ascii wide

    condition:
        any of them
}
