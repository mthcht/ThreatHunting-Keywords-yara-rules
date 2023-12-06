rule Lovely_Potato
{
    meta:
        description = "Detection patterns for the tool 'Lovely-Potato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Lovely-Potato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lovely Potato (automating juicy potato) Powershell wrapper of Decoders JuicyPotato for easy exploitation. This entirely depends on the original Juicy Potato binary and utilizes his test_clsid.bat. another Local Privilege Escalation tool. from a Windows Service Accounts to NT AUTHORITY\SYSTEM
        // Reference: https://github.com/TsukiCTF/Lovely-Potato
        $string1 = /Lovely\-Potato/ nocase ascii wide

    condition:
        any of them
}
