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
        $string1 = /.{0,1000}\/RuralBishop\.git.{0,1000}/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string2 = /.{0,1000}FE4414D9\-1D7E\-4EEB\-B781\-D278FE7A5619.{0,1000}/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string3 = /.{0,1000}rasta\-mouse\/RuralBishop.{0,1000}/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string4 = /.{0,1000}RuralBishop\.csproj.{0,1000}/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string5 = /.{0,1000}RuralBishop\.exe.{0,1000}/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string6 = /.{0,1000}RuralBishop\.sln.{0,1000}/ nocase ascii wide
        // Description: creates a local RW section in UrbanBishop and then maps that section as RX into a remote process
        // Reference: https://github.com/rasta-mouse/RuralBishop
        $string7 = /.{0,1000}RuralBishop\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
