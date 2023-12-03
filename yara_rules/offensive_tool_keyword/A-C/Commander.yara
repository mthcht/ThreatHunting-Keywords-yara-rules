rule Commander
{
    meta:
        description = "Detection patterns for the tool 'Commander' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Commander"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string1 = /.{0,1000}\sc2_server\.py.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string2 = /.{0,1000}\/c2_server\.py.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string3 = /.{0,1000}\\c2_server\.py.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string4 = /.{0,1000}c2_server\.py\s.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string5 = /.{0,1000}c2\-sessions\sping.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string6 = /.{0,1000}c2\-sessions\squit.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string7 = /.{0,1000}cbe60ddb0c22d6a5743901dd06d855958a68a90ab0820665acd1e7b53f0a9c71.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string8 = /.{0,1000}https:\/\/127\.0\.0\.1:5000\/register.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string9 = /.{0,1000}https:\/\/127\.0\.0\.1:5000\/results\/.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string10 = /.{0,1000}https:\/\/127\.0\.0\.1:5000\/tasks\/.{0,1000}/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string11 = /.{0,1000}voukatas\/Commander.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
