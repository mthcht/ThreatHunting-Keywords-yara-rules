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
        $string1 = /.{0,1000}\/pspy\s\-.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string2 = /.{0,1000}\/pspy\.git.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string3 = /.{0,1000}\/pspy\.go.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string4 = /.{0,1000}\/pspy\/cmd.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string5 = /.{0,1000}\/pspy32.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string6 = /.{0,1000}\/pspy64.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string7 = /.{0,1000}\/psscanner\.go.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string8 = /.{0,1000}DominicBreuker\/pspy.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string9 = /.{0,1000}pspy.{0,1000}psscanner/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string10 = /.{0,1000}pspy32\s\-.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string11 = /.{0,1000}pspy64\s\-.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string12 = /.{0,1000}pspy\-build:latest.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string13 = /.{0,1000}pspy\-development:latest.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string14 = /.{0,1000}pspy\-example:latest.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string15 = /.{0,1000}pspy\-master.{0,1000}/ nocase ascii wide
        // Description: Monitor linux processes without root permissions
        // Reference: https://github.com/DominicBreuker/pspy
        $string16 = /.{0,1000}pspy\-testing:latest.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
