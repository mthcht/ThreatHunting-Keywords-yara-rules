rule ScareCrow
{
    meta:
        description = "Detection patterns for the tool 'ScareCrow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScareCrow"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string1 = /\s\-I\s.{0,1000}\.bin\s.{0,1000}\s\-Loader\sdll/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string2 = /\.\/ScareCrow\s\-/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string3 = /\.\/ScareCrow/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string4 = /optiv\/ScareCrow/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string5 = /ScareCrow\s.{0,1000}\-loader\s/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string6 = /ScareCrow.{0,1000}windows_amd64\.exe/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string7 = /ScareCrow\.go/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string8 = /ScareCrow_.{0,1000}_darwin_amd64/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string9 = /ScareCrow_.{0,1000}_linux_amd64/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string10 = /ScareCrow_.{0,1000}amd64/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string11 = /ScareCrow_checksums\.txt/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string12 = /ScareCrow\s\-/ nocase ascii wide

    condition:
        any of them
}
