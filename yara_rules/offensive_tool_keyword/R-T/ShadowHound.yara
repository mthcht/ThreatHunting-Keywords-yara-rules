rule ShadowHound
{
    meta:
        description = "Detection patterns for the tool 'ShadowHound' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShadowHound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string1 = /\sbofhound\.py/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string2 = /\/bofhound\.py/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string3 = /\/ShadowHound\.git/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string4 = /\\bofhound\.py/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string5 = "a510e14853234b49b9053a18264aa29e4dfbf467edae47afe13a08d57d34dad4" nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string6 = /Author\:\sYehuda\sSmirnov\s\(X\:\s\@yudasm_\sBlueSky\:\s\@yudasm\.bsky\.social\)/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string7 = "b7ae4b58d31453da02817000dd7465ab68434f43e22d2b7a5ffc73f3fa65f6cd" nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string8 = "Friends-Security/ShadowHound" nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string9 = "shadowhound -Command " nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string10 = "ShadowHound-ADM " nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string11 = /ShadowHound\-ADM\.ps1/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string12 = "ShadowHound-DS " nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string13 = /ShadowHound\-DS\(/ nocase ascii wide
        // Description: set of PowerShell scripts for Active Directory enumeration
        // Reference: https://github.com/Friends-Security/ShadowHound
        $string14 = /ShadowHound\-DS\.ps1/ nocase ascii wide

    condition:
        any of them
}
