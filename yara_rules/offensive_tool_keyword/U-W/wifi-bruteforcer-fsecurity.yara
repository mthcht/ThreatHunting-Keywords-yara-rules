rule wifi_bruteforcer_fsecurity
{
    meta:
        description = "Detection patterns for the tool 'wifi-bruteforcer-fsecurity' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wifi-bruteforcer-fsecurity"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Wifi bruteforcer
        // Reference: https://github.com/faizann24/wifi-bruteforcer-fsecurify
        $string1 = /wifi\-bruteforcer/ nocase ascii wide

    condition:
        any of them
}
