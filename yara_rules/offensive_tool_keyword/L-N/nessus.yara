rule nessus
{
    meta:
        description = "Detection patterns for the tool 'nessus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nessus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string1 = /\/opt\/nessus\// nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string2 = /log4shell.*\.nessus\.org/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string3 = /nessus.*\s\-\-set\slisten_address\=127\.0\.0\.1/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string4 = /Nessus\-.*\.deb/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string5 = /Nessus\-.*\.dmg/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string6 = /Nessus\-.*\.msi/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string7 = /Nessus\-.*\.rpm/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string8 = /Nessus\-.*\.tar\.gz/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string9 = /Nessus\-.*\.txz/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string10 = /nessuscli\sfetch/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string11 = /nessuscli\sfix/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string12 = /nessus\-updates.*\.tar\.gz/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string13 = /plugins\.nessus\.org\./ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string14 = /systemctl\sstart\snessusd/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string15 = /tenable\.com\/downloads\/nessus/ nocase ascii wide

    condition:
        any of them
}