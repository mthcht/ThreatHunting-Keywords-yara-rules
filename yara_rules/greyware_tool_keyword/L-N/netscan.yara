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
        $string1 = /\/netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string2 = /\\netscan\.exe/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string3 = /\\netscan\.lic/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string4 = /\\netscan\.xml/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string5 = /\\SoftPerfect\sNetwork\sScanner/ nocase ascii wide
        // Description: SoftPerfect Network Scanner abused by threat actor
        // Reference: https://www.softperfect.com/products/networkscanner/
        $string6 = /netscan_setup\.exe/ nocase ascii wide

    condition:
        any of them
}
