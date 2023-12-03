rule DOME
{
    meta:
        description = "Detection patterns for the tool 'DOME' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DOME"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string1 = /.{0,1000}\sdome\.py.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string2 = /.{0,1000}\.\/dome\.py.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string3 = /.{0,1000}\/Dome\.git.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string4 = /.{0,1000}dome\.py\s.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string5 = /.{0,1000}\-m\s.{0,1000}\s\-d\s.{0,1000}\s\-w\s.{0,1000}\s\-\-top\-web\-ports.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string6 = /.{0,1000}v4d1\/Dome.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string7 = /.{0,1000}wordlists\/subdomains\-5000\.txt.{0,1000}/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string8 = /.{0,1000}wordlists\/top1million\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
