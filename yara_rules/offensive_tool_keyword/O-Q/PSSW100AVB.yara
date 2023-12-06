rule PSSW100AVB
{
    meta:
        description = "Detection patterns for the tool 'PSSW100AVB' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSSW100AVB"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This is the PSSW100AVB (Powershell Scripts With 100% AV Bypass) Framework.A list of useful Powershell scripts with 100% AV bypass ratio
        // Reference: https://github.com/tihanyin/PSSW100AVB
        $string1 = /\/PSSW100AVB/ nocase ascii wide
        // Description: This is the PSSW100AVB (Powershell Scripts With 100% AV Bypass) Framework.A list of useful Powershell scripts with 100% AV bypass ratio
        // Reference: https://github.com/tihanyin/PSSW100AVB
        $string2 = /AMSI_bypass_20.{0,1000}\.ps1/ nocase ascii wide
        // Description: This is the PSSW100AVB (Powershell Scripts With 100% AV Bypass) Framework.A list of useful Powershell scripts with 100% AV bypass ratio
        // Reference: https://github.com/tihanyin/PSSW100AVB
        $string3 = /LsassDump_20.{0,1000}\.ps1/ nocase ascii wide
        // Description: This is the PSSW100AVB (Powershell Scripts With 100% AV Bypass) Framework.A list of useful Powershell scripts with 100% AV bypass ratio
        // Reference: https://github.com/tihanyin/PSSW100AVB
        $string4 = /ReverseShell_20.{0,1000}\.ps1/ nocase ascii wide

    condition:
        any of them
}
