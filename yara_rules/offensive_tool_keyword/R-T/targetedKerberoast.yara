rule targetedKerberoast
{
    meta:
        description = "Detection patterns for the tool 'targetedKerberoast' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "targetedKerberoast"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string1 = /.{0,1000}\/targetedKerberoast.{0,1000}/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string2 = /.{0,1000}kerberoastables\.txt.{0,1000}/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string3 = /.{0,1000}targetedKerberoast\.git.{0,1000}/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string4 = /.{0,1000}targetedKerberoast\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string5 = /.{0,1000}targetedKerberoast\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
