rule LAZYPARIAH
{
    meta:
        description = "Detection patterns for the tool 'LAZYPARIAH' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAZYPARIAH"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LAZYPARIAH - A Tool For Generating Reverse Shell Payloads On The Fly
        // Reference: https://github.com/octetsplicer/LAZYPARIAH
        $string1 = /.{0,1000}\slazypariah.{0,1000}/ nocase ascii wide
        // Description: LAZYPARIAH - A Tool For Generating Reverse Shell Payloads On The Fly
        // Reference: https://github.com/octetsplicer/LAZYPARIAH
        $string2 = /.{0,1000}lazypariah\s.{0,1000}/ nocase ascii wide
        // Description: LAZYPARIAH - A Tool For Generating Reverse Shell Payloads On The Fly
        // Reference: https://github.com/octetsplicer/LAZYPARIAH
        $string3 = /.{0,1000}lazypariah\.svg.{0,1000}/ nocase ascii wide
        // Description: LAZYPARIAH - A Tool For Generating Reverse Shell Payloads On The Fly
        // Reference: https://github.com/octetsplicer/LAZYPARIAH
        $string4 = /.{0,1000}octetsplicer\/LAZYPARIAH.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
