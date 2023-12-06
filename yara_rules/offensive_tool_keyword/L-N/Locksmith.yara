rule Locksmith
{
    meta:
        description = "Detection patterns for the tool 'Locksmith' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Locksmith"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string1 = /\s\-InputPath\s\.\\TrustedForests\.txt/ nocase ascii wide
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string2 = /\/Locksmith\.git/ nocase ascii wide
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string3 = /Invoke\-Locksmith\.ps1/ nocase ascii wide
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string4 = /Locksmith\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
