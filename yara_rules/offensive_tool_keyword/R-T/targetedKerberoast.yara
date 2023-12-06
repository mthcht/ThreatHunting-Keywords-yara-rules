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
        $string1 = /\/targetedKerberoast/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string2 = /kerberoastables\.txt/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string3 = /targetedKerberoast\.git/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string4 = /targetedKerberoast\.py/ nocase ascii wide
        // Description: Kerberoast with ACL abuse capabilities
        // Reference: https://github.com/ShutdownRepo/targetedKerberoast
        $string5 = /targetedKerberoast\-main/ nocase ascii wide

    condition:
        any of them
}
