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
        $string1 = /.{0,1000}\/bloodyAD\.git.{0,1000}/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string2 = /.{0,1000}bloodyAD\s\-.{0,1000}/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string3 = /.{0,1000}bloodyAD\.py.{0,1000}/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string4 = /.{0,1000}bloodyAD\-main.{0,1000}/ nocase ascii wide
        // Description: BloodyAD is an Active Directory Privilege Escalation Framework
        // Reference: https://github.com/CravateRouge/bloodyAD
        $string5 = /.{0,1000}CravateRouge\/bloodyAD.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
