rule netcat
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
        $string1 = /nc\s.*\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: netcat shell listener
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string2 = /nc\s\-u\s\-lvp\s/ nocase ascii wide
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string3 = /ncat\s.*\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4 = /ncat\s\-\-udp\s.*\s\-e\s\/bin\/bash/ nocase ascii wide
        // Description: Netcat is a featured networking utility which reads and writes data across network connections
        // Reference: http://netcat.sourceforge.net/
        $string5 = /netCat/ nocase ascii wide
        // Description: Netcat is a featured networking utility which reads and writes data across network connections. using the TCP/IP protocol It is designed to be a reliable back-end tool that can be used directly or easily driven by other programs and scripts. At the same time. it is a feature-rich network debugging and exploration tool. since it can create almost any kind of connection you would need and has several interesting built-in capabilities
        // Reference: http://netcat.sourceforge.net/
        $string6 = /nc\s\-vz\s/ nocase ascii wide

    condition:
        any of them
}