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
        $string1 = /.{0,1000}\spolenum\.py.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string2 = /.{0,1000}\/polenum\.py.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string3 = /.{0,1000}\/usr\/bin\/polenum.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string4 = /.{0,1000}\\polenum\.py.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string5 = /.{0,1000}apt\sinstall\spolenum.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string6 = /.{0,1000}polenum\s.{0,1000}\-protocols\s.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string7 = /.{0,1000}polenum\s\-h.{0,1000}/ nocase ascii wide
        // Description: Uses Impacket Library to get the password policy from a windows machine
        // Reference: https://salsa.debian.org/pkg-security-team/polenum
        $string8 = /polenum\s.{0,1000}:.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
