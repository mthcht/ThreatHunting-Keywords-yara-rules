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
        $string1 = /mshta\shttp.{0,1000}\.hta/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string2 = /mshta\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string3 = /mshta\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string4 = /mshta\.exe.{0,1000}\shttp\:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string5 = /mshta\.exe.{0,1000}\shttps\:\/\// nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string6 = /mshta\.exe.{0,1000}\sjavascript\:.{0,1000}script\:https\:/ nocase ascii wide
        // Description: mshta abused by attackers
        // Reference: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
        $string7 = /mshta\.exe.{0,1000}\svbscript\:Close\(Execute\(.{0,1000}script\:https\:\/\/.{0,1000}\.sct/ nocase ascii wide

    condition:
        any of them
}
