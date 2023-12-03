rule AD_Enumeration_Hunt
{
    meta:
        description = "Detection patterns for the tool 'AD_Enumeration_Hunt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AD_Enumeration_Hunt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This repository contains a collection of PowerShell scripts and commands that can be used for Active Directory (AD) penetration testing and security assessment
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt
        $string1 = /.{0,1000}\/AD_Enumeration_Hunt.{0,1000}/ nocase ascii wide
        // Description: This repository contains a collection of PowerShell scripts and commands that can be used for Active Directory (AD) penetration testing and security assessment
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt
        $string2 = /.{0,1000}AD_Enumeration_Hunt\.ps1.{0,1000}/ nocase ascii wide
        // Description: This repository contains a collection of PowerShell scripts and commands that can be used for Active Directory (AD) penetration testing and security assessment
        // Reference: https://github.com/alperenugurlu/AD_Enumeration_Hunt
        $string3 = /.{0,1000}AD_Enumeration_Hunt\-alperen_ugurlu_hack.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
