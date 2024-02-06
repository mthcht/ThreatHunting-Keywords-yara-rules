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
        $string1 = /\sc2_server\.py/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string2 = /\/c2_server\.py/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string3 = /\\c2_server\.py/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string4 = /c2_server\.py\s/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string5 = /c2\-sessions\sping/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string6 = /c2\-sessions\squit/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string7 = /cbe60ddb0c22d6a5743901dd06d855958a68a90ab0820665acd1e7b53f0a9c71/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string8 = /https\:\/\/127\.0\.0\.1\:5000\/register/ nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string9 = /https\:\/\/127\.0\.0\.1\:5000\/results\// nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string10 = /https\:\/\/127\.0\.0\.1\:5000\/tasks\// nocase ascii wide
        // Description: A command and control (C2) server
        // Reference: https://github.com/voukatas/Commander
        $string11 = /voukatas\/Commander/ nocase ascii wide

    condition:
        any of them
}
