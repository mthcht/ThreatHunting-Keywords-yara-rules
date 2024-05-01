rule Ammyy_Admin
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string1 = /\\aa_nts\.dll/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string2 = /\\AA_v3\.exe/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string3 = /\\AA_v3\.log/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string4 = /\\AMMYY\\access\.log/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string5 = /\\ControlSet001\\Control\\SafeBoot\\Network\\AmmyyAdmin_/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string6 = /\\ProgramData\\AMMYY\\/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string7 = /\\SOFTWARE\\Ammyy\\Admin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string8 = /AA_v3\.exe.{0,1000}\s\-elevated/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string9 = /AA_v3\.exe.{0,1000}\s\-service\s\-lunch/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string10 = /Ammyy\sAdmin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string11 = /Ammyy\sLLC/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string12 = /rl\.ammyy\.com\// nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string13 = /SPR\/Ammyy\.R/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string14 = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string15 = /www\.ammyy\.com\/files\/v/ nocase ascii wide

    condition:
        any of them
}
