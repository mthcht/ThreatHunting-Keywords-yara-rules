rule mshta
{
    meta:
        description = "Detection patterns for the tool 'mshta' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mshta"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string1 = /.{0,1000}mshta\shttp.{0,1000}\.hta.{0,1000}/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string2 = /.{0,1000}mshta\sjavascript:.{0,1000}script:https:.{0,1000}/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string3 = /.{0,1000}mshta\svbscript:Close\(Execute\(.{0,1000}script:https:\/\/.{0,1000}\.sct.{0,1000}/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string4 = /.{0,1000}mshta\.exe.{0,1000}\shttp:\/\/.{0,1000}/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string5 = /.{0,1000}mshta\.exe.{0,1000}\shttps:\/\/.{0,1000}/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string6 = /.{0,1000}mshta\.exe.{0,1000}\sjavascript:.{0,1000}script:https:.{0,1000}/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string7 = /.{0,1000}mshta\.exe.{0,1000}\svbscript:Close\(Execute\(.{0,1000}script:https:\/\/.{0,1000}\.sct.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
