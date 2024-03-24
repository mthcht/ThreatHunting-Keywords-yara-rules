rule nullinux
{
    meta:
        description = "Detection patterns for the tool 'nullinux' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nullinux"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string1 = /\snullinux\.py/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string2 = /\/nullinux\.git/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string3 = /\/nullinux\.py/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string4 = /\/nullinux_users\.txt/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string5 = /\/usr\/local\/bin\/nullinux/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string6 = /\]\sStarting\snullinux\ssetup\sscript/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string7 = /e4df5a904c8eb505cb63d9905c398f632cf97ba193a6e25569d561d44f69e623/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string8 = /enum_enumdomusers\(/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string9 = /m8sec\/nullinux/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string10 = /nullinux\s\-rid\s\-range\s/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string11 = /nullinux\s\-shares\s\-U\s/ nocase ascii wide
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string12 = /nullinux\s\-users\s/ nocase ascii wide

    condition:
        any of them
}
