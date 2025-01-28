rule Ammyy_Admin
{
    meta:
        description = "Detection patterns for the tool 'Ammyy Admin' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ammyy Admin"
        rule_category = "signature_keyword"

    strings:
        // Description: Ammyy Admin is a remote desktop software application abudsed by attackers
        // Reference: https://www.ammyy.com
        $string1 = "PUA:Win32/AmmyyAdmin" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string2 = "PUA:Win32/AmmyyAdmin" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: https://www.ammyy.com
        $string3 = "RemoteAccess:Win32/AmmyAdmin" nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: https://www.ammyy.com
        $string4 = /SPR\/Ammyy\.R/ nocase ascii wide
        // Description: Antiviurs signature_keyword
        // Reference: N/A
        $string5 = /Win32\.PUA\.AmmyyAdmin/ nocase ascii wide

    condition:
        any of them
}
