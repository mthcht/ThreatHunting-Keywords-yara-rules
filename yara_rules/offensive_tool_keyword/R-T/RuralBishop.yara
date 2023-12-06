rule RuralBishop
{
    meta:
        description = "Detection patterns for the tool 'RuralBishop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RuralBishop"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string1 = /\/RuralBishop\.git/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string2 = /FE4414D9\-1D7E\-4EEB\-B781\-D278FE7A5619/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string3 = /rasta\-mouse\/RuralBishop/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string4 = /RuralBishop\.csproj/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string5 = /RuralBishop\.exe/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string6 = /RuralBishop\.sln/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string7 = /RuralBishop\-master/ nocase ascii wide

    condition:
        any of them
}
