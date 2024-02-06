rule polenum
{
    meta:
        description = "Detection patterns for the tool 'polenum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "polenum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string1 = /\spolenum\.py/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string2 = /\/polenum\.py/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string3 = /\/usr\/bin\/polenum/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string4 = /\\polenum\.py/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string5 = /apt\sinstall\spolenum/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string6 = /polenum\s.{0,1000}\-protocols\s/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string7 = /polenum\s\-h/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string8 = /polenum\s.{0,1000}\:/ nocase ascii wide

    condition:
        any of them
}
