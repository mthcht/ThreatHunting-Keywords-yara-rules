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
        $string1 = /.{0,1000}\sadcsync\.py.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string2 = /.{0,1000}\/adcsync\.git.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string3 = /.{0,1000}\/adcsync\.py.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string4 = /.{0,1000}\\adcsync\.py.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string5 = /.{0,1000}adcsync\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string6 = /.{0,1000}Certipy\snot\sfound\.\sPlease\sinstall\sCertipy\sbefore\srunning\sADCSync.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string7 = /.{0,1000}certipy\sreq\s\-u\s.{0,1000}\s\-p\s.{0,1000}\s\-target\-ip\s.{0,1000}\s\-dc\-ip\s.{0,1000}\s\-ca\s.{0,1000}/ nocase ascii wide
        // Description: Use ESC1 to perform a makeshift DCSync and dump hashes
        // Reference: https://github.com/JPG0mez/ADCSync
        $string8 = /.{0,1000}JPG0mez\/ADCSync.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
