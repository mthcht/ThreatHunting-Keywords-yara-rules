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
        $string1 = /.{0,1000}\s\-I\s.{0,1000}\.bin\s.{0,1000}\s\-Loader\sdll.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string2 = /.{0,1000}\.\/ScareCrow\s\-.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string3 = /.{0,1000}\.\/ScareCrow.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string4 = /.{0,1000}optiv\/ScareCrow.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string5 = /.{0,1000}ScareCrow\s.{0,1000}\-loader\s.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string6 = /.{0,1000}ScareCrow.{0,1000}windows_amd64\.exe.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string7 = /.{0,1000}ScareCrow\.go.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string8 = /.{0,1000}ScareCrow_.{0,1000}_darwin_amd64.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string9 = /.{0,1000}ScareCrow_.{0,1000}_linux_amd64.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string10 = /.{0,1000}ScareCrow_.{0,1000}amd64.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string11 = /.{0,1000}ScareCrow_checksums\.txt.{0,1000}/ nocase ascii wide
        // Description: ScareCrow - Payload creation framework designed around EDR bypass.
        // Reference: https://github.com/optiv/ScareCrow
        $string12 = /ScareCrow\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
