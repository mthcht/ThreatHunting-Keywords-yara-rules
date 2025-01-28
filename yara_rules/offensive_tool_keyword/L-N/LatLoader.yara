rule LatLoader
{
    meta:
        description = "Detection patterns for the tool 'LatLoader' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LatLoader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string1 = /\sLatLoader\.py/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string2 = /\/LatLoader\.git/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string3 = /\/LatLoader\.py/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string4 = /\[\+\]\sLooking\sfor\sthe\sSSN\svia\sHalos\sGate/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string5 = /\\LatLoader\.py/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string6 = /\\LatLoader\-main/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string7 = "27f70a1d533f7a3b8703d89904ae4541d96c8c656661872a495f592f9ed80d9e" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string8 = "45787955618ba3211b89021ddf23ecc5d2b55397a006190455c4070dad964572" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string9 = /cmd\.exe\s\/c\sC\:\\\\Windows\\\\DiskSnapShot\.exe\s\&\&\secho\s\-\-path\sC\:\\\\Windows\\\\CCMCache\\\\cache/ nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string10 = "f0f8f8de178f91de8fe054b6450fa0d2291ad7693035f2c52df800e9168fb22d" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string11 = "icyguider/LatLoader" nocase ascii wide
        // Description: PoC module to demonstrate automated lateral movement with the Havoc C2 framework
        // Reference: https://github.com/icyguider/LatLoader
        $string12 = "OPERATORCHANGEMEPLZZZ" nocase ascii wide

    condition:
        any of them
}
