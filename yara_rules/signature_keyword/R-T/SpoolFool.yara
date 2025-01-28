rule SpoolFool
{
    meta:
        description = "Detection patterns for the tool 'SpoolFool' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpoolFool"
        rule_category = "signature_keyword"

    strings:
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string1 = "A Variant Of Win64/AddUser" nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string2 = "ATK/SpoolFool-A" nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string3 = /Exp\.CVE\-2022\-21999/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string4 = /Exploit\.CVE202222718\.MSIL/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string5 = /Generic\.Exploit\.CVE\-2022\-22718\.A\.2798221A/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string6 = /HEUR\:Exploit\.MSIL\.CVE\-2022\-22718\.gen/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string7 = /MSIL\/CVE_2022_22718\.A\!exploit/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string8 = /MSIL\/Exploit\.CVE\-2022\-22718\.A/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string9 = /Trojan\.AddUser/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string10 = /VirTool\:MSIL\/Spfolz\.A\!MTB/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string11 = /Win\.Exploit\.Exploitx\-9942911\-0/ nocase ascii wide

    condition:
        any of them
}
