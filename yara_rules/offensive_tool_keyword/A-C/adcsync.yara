rule adcsync
{
    meta:
        description = "Detection patterns for the tool 'adcsync' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adcsync"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string1 = /\sadcsync\.py/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string2 = /\/adcsync\.git/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string3 = /\/adcsync\.py/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string4 = /\\adcsync\.py/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string5 = /adcsync\.py\s\-/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string6 = /Certipy\snot\sfound\.\sPlease\sinstall\sCertipy\sbefore\srunning\sADCSync/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string7 = /certipy\sreq\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-target\-ip\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-ca\s/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string8 = /JPG0mez\/ADCSync/ nocase ascii wide

    condition:
        any of them
}
