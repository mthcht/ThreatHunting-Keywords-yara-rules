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
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string2 = /NetSh\sAdvfirewall\sset\sallprofiles\sstate\soff/ nocase ascii wide
        // Description: script to dismantle complete windows defender protection and even bypass tamper protection  - Disable Windows-Defender Permanently.
        // Reference: https://github.com/swagkarna/Defeat-Defender-V1.2.0
        $string3 = /netsh\sadvfirewall\sset\sallprofiles\sstate\soff/ nocase ascii wide
        // Description: adding a executable in user appdata folder to the allowed programs
        // Reference: https://tria.ge/231006-ydmxjsfe5s/behavioral1/analog?proc=66
        $string4 = /netsh\sfirewall\sadd\sallowedprogram\s\"C\:\\Users\\.{0,1000}\\AppData\\.{0,1000}\.exe\"\s\".{0,1000}\.exe\"\sENABLE/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string5 = /netsh\sfirewall\sset\sopmode\sdisable/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string6 = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,1000}\sconnectport\=.{0,1000}\sconnectaddress\=/ nocase ascii wide
        // Description: The actor has used the following commands to enable port forwarding [T1090] on the host
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string7 = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,1000}listenaddress\=.{0,1000}\slistenport\=.{0,1000}connectaddress\=.{0,1000}connectport/ nocase ascii wide
        // Description: attempt to remove port proxy configurations
        // Reference: https://media.defense.gov/2024/Feb/07/2003389936/-1/-1/0/JOINT-GUIDANCE-IDENTIFYING-AND-MITIGATING-LOTL.PDF
        $string8 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenaddress\=0\.0\.0\.0\slistenport\=/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string9 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenport\=/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string10 = /netsh\sinterface\sportproxy\sshow\sv4tov4/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string11 = /netsh\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string12 = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide

    condition:
        any of them
}
