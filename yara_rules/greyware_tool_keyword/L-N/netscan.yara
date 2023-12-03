rule netscan
{
    meta:
        description = "Detection patterns for the tool 'netscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "netscan"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string1 = /.{0,1000}\/netscan\.exe.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2 = /.{0,1000}\\netscan\.exe.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3 = /.{0,1000}\\netscan\.lic.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4 = /.{0,1000}\\netscan\.xml.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5 = /.{0,1000}\\SoftPerfect\sNetwork\sScanner.{0,1000}/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6 = /.{0,1000}netscan_setup\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
