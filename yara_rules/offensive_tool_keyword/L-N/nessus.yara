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
        $string1 = /.{0,1000}\/opt\/nessus\/.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string2 = /.{0,1000}log4shell.{0,1000}\.nessus\.org.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string3 = /.{0,1000}nessus.{0,1000}\s\-\-set\slisten_address\=127\.0\.0\.1.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string4 = /.{0,1000}Nessus\-.{0,1000}\.deb.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string5 = /.{0,1000}Nessus\-.{0,1000}\.dmg.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string6 = /.{0,1000}Nessus\-.{0,1000}\.msi.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string7 = /.{0,1000}Nessus\-.{0,1000}\.rpm.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string8 = /.{0,1000}Nessus\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string9 = /.{0,1000}Nessus\-.{0,1000}\.txz.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string10 = /.{0,1000}nessuscli\sfetch.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string11 = /.{0,1000}nessuscli\sfix.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string12 = /.{0,1000}nessus\-updates.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string13 = /.{0,1000}plugins\.nessus\.org\..{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string14 = /.{0,1000}systemctl\sstart\snessusd.{0,1000}/ nocase ascii wide
        // Description: Vulnerability scanner
        // Reference: https://fr.tenable.com/products/nessus
        $string15 = /.{0,1000}tenable\.com\/downloads\/nessus.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
