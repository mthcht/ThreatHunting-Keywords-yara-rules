rule bloodyAD
{
    meta:
        description = "Detection patterns for the tool 'bloodyAD' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bloodyAD"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string1 = /\/bloodyAD\.git/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string2 = /bloodyAD\s\-/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string3 = /bloodyAD\.py/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string4 = /bloodyAD\-main/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string5 = /CravateRouge\/bloodyAD/ nocase ascii wide

    condition:
        any of them
}
