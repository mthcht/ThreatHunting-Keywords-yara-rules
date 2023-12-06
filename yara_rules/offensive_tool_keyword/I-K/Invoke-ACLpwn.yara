rule Invoke_ACLpwn
{
    meta:
        description = "Detection patterns for the tool 'Invoke-ACLpwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-ACLpwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Invoke-ACLpwn is a tool that automates the discovery and pwnage of ACLs in Active Directory that are unsafe configured.
        // Reference: https://github.com/fox-it/Invoke-ACLPwn
        $string1 = /Invoke\-ACLPwn/ nocase ascii wide

    condition:
        any of them
}
