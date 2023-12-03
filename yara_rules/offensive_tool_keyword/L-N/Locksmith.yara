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
        $string1 = /.{0,1000}\s\-InputPath\s\.\\TrustedForests\.txt.{0,1000}/ nocase ascii wide
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string2 = /.{0,1000}\/Locksmith\.git.{0,1000}/ nocase ascii wide
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string3 = /.{0,1000}Invoke\-Locksmith\.ps1.{0,1000}/ nocase ascii wide
        // Description: A tiny tool to identify and remediate common misconfigurations in Active Directory Certificate Services
        // Reference: https://github.com/TrimarcJake/Locksmith
        $string4 = /.{0,1000}Locksmith\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
