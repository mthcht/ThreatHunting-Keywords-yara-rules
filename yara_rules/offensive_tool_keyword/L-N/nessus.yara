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
        $string1 = "/opt/nessus/" nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string2 = /log4shell.{0,1000}\.nessus\.org/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string3 = /nessus.{0,1000}\s\-\-set\slisten_address\=127\.0\.0\.1/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string4 = /Nessus\-.{0,1000}\.deb/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string5 = /Nessus\-.{0,1000}\.dmg/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string6 = /Nessus\-.{0,1000}\.msi/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string7 = /Nessus\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string8 = /Nessus\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string9 = /Nessus\-.{0,1000}\.txz/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string10 = "nessuscli fetch" nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string11 = "nessuscli fix" nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string12 = /nessus\-updates.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string13 = /plugins\.nessus\.org\./ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string14 = "systemctl start nessusd" nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string15 = /tenable\.com\/downloads\/nessus/ nocase ascii wide

    condition:
        any of them
}
