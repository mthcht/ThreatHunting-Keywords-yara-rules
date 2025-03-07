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
        $string1 = /\snullinux\.py/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string2 = /\/nullinux\.git/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string3 = /\/nullinux\.py/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string4 = /\/nullinux_users\.txt/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string5 = "/usr/local/bin/nullinux"
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string6 = /\]\sStarting\snullinux\ssetup\sscript/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string7 = "e4df5a904c8eb505cb63d9905c398f632cf97ba193a6e25569d561d44f69e623"
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string8 = /enum_enumdomusers\(/
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string9 = "m8sec/nullinux"
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string10 = "nullinux -rid -range "
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string11 = "nullinux -shares -U "
        // Description: Internal penetration testing tool for Linux that can be used to enumerate OS information/domain information/ shares/ directories and users through SMB.
        // Reference: https://github.com/m8sec/nullinux
        $string12 = "nullinux -users "

    condition:
        any of them
}
