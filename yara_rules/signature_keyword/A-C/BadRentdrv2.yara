rule BadRentdrv2
{
    meta:
        description = "Detection patterns for the tool 'BadRentdrv2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadRentdrv2"
        rule_category = "signature_keyword"

    strings:
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string1 = /A\sVariant\sOf\sWin64\/KillProc\.V/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string2 = /Exploitable\sHangzhou\sRentDrv\sDriver\s\(PUA\)/ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string3 = /PUA\.Win64\.Rentdrv\./ nocase ascii wide
        // Description: A vulnerable driver (BYOVD) capable of terminating several EDRs and antivirus software
        // Reference: https://github.com/keowu/BadRentdrv2
        $string4 = /Win64\/RentDrv\.A\sPotentially\sUnsafe/ nocase ascii wide

    condition:
        any of them
}
