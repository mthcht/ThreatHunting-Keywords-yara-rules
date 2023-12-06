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
        $string1 = /\sdome\.py/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string2 = /\.\/dome\.py/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string3 = /\/Dome\.git/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string4 = /dome\.py\s/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string5 = /\-m\s.{0,1000}\s\-d\s.{0,1000}\s\-w\s.{0,1000}\s\-\-top\-web\-ports/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string6 = /v4d1\/Dome/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string7 = /wordlists\/subdomains\-5000\.txt/ nocase ascii wide
        // Description: DOME - A subdomain enumeration tool
        // Reference: https://github.com/v4d1/Dome
        $string8 = /wordlists\/top1million\.txt/ nocase ascii wide

    condition:
        any of them
}
