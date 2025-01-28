rule netcat
{
    meta:
        description = "Detection patterns for the tool 'netcat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netcat"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ncat reverse shell
        // Reference: https://nmap.org/ncat/
        $string1 = /\/netcat\-win32\-.{0,1000}\.zip/
        // Description: ncat reverse shell
        // Reference: https://nmap.org/ncat/
        $string2 = /\\nc\.exe/ nocase ascii wide
        // Description: ncat reverse shell
        // Reference: https://nmap.org/ncat/
        $string3 = /\\netcat\-win32\-.{0,1000}\.zip/ nocase ascii wide
        // Description: netcat shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string4 = /nc\s.{0,1000}\s\-e\s\/bin\/bash/
        // Description: netcat shell listener
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string5 = "nc -u -lvp " nocase ascii wide
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string6 = /ncat\s.{0,1000}\s\-e\s\/bin\/bash/
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string7 = /ncat\s\-\-udp\s.{0,1000}\s\-e\s\/bin\/bash/
        // Description: ncat reverse shell
        // Reference: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
        $string8 = /netcat\.exe/ nocase ascii wide

    condition:
        any of them
}
