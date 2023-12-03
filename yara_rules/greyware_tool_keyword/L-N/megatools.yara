rule megatools
{
    meta:
        description = "Detection patterns for the tool 'megatools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "megatools"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string1 = /.{0,1000}\/megatools\.exe.{0,1000}/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string2 = /.{0,1000}\\megatools\-.{0,1000}\-win64\\.{0,1000}/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string3 = /.{0,1000}\\megatools\.exe.{0,1000}/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string4 = /.{0,1000}\\Users\\.{0,1000}\\AppData\\Local\\Temp\\.{0,1000}\.megatools\.cache.{0,1000}/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string5 = /.{0,1000}megatools\scopy\s\-l\s.{0,1000}\s\-r\s.{0,1000}/ nocase ascii wide
        // Description: Megatools is a collection of free and open source programs for accessing Mega service from a command line. Abused by attackers for data exfiltration
        // Reference: https://github.com/megous/megatools
        $string6 = /.{0,1000}megatools\sput\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
