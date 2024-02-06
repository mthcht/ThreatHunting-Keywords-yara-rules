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
        // Reference: 
        $string1 = /netsh\sadvfirewall\sfirewall\sshow\srule\sname\=all/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string2 = /NetSh\sAdvfirewall\sset\sallprofiles\sstate\soff/ nocase ascii wide
        // Description: adding a executable in user appdata folder to the allowed programs
        // Reference: https://tria.ge/231006-ydmxjsfe5s/behavioral1/analog?proc=66
        $string3 = /netsh\sfirewall\sadd\sallowedprogram\s\"C\:\\Users\\.{0,1000}\\AppData\\.{0,1000}\.exe\"\s\".{0,1000}\.exe\"\sENABLE/ nocase ascii wide
        // Description: Disable Windows Firewall
        // Reference: N/A
        $string4 = /netsh\sfirewall\sset\sopmode\sdisable/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string5 = /netsh\sinterface\sportproxy\sadd\sv4tov4\slistenport\=.{0,1000}\sconnectport\=.{0,1000}\sconnectaddress\=/ nocase ascii wide
        // Description: The actor has used the following commands to enable port forwarding [T1090] on the host
        // Reference: https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF
        $string6 = /netsh\sinterface\sportproxy\sadd\sv4tov4.{0,1000}listenaddress\=.{0,1000}\slistenport\=.{0,1000}connectaddress\=.{0,1000}connectport/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string7 = /netsh\sinterface\sportproxy\sdelete\sv4tov4\slistenport\=/ nocase ascii wide
        // Description: commands from wmiexec2.0 -  is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string8 = /netsh\sinterface\sportproxy\sshow\sv4tov4/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string9 = /netsh\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide
        // Description: display saved Wi-Fi profiles including plaintext passwords on a Windows system
        // Reference: N/A
        $string10 = /netsh\.exe\swlan\sshow\sprofiles\skey\=clear/ nocase ascii wide

    condition:
        any of them
}
