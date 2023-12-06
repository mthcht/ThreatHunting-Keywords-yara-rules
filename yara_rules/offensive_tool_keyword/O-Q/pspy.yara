rule pspy
{
    meta:
        description = "Detection patterns for the tool 'pspy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pspy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string1 = /\/pspy\s\-/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string2 = /\/pspy\.git/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string3 = /\/pspy\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string4 = /\/pspy\/cmd/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string5 = /\/pspy32/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string6 = /\/pspy64/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string7 = /\/psscanner\.go/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string8 = /DominicBreuker\/pspy/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string9 = /pspy.{0,1000}psscanner/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string10 = /pspy32\s\-/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string11 = /pspy64\s\-/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string12 = /pspy\-build:latest/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string13 = /pspy\-development:latest/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string14 = /pspy\-example:latest/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string15 = /pspy\-master/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string16 = /pspy\-testing:latest/ nocase ascii wide

    condition:
        any of them
}
