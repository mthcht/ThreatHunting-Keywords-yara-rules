rule Generate_Macro
{
    meta:
        description = "Detection patterns for the tool 'Generate-Macro' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Generate-Macro"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Generate-Macro is a standalone PowerShell script that will generate a malicious Microsoft Office document with a specified payload and persistence method.
        // Reference: https://github.com/enigma0x3/Generate-Macro
        $string1 = /Generate\-Macro\.ps1/ nocase ascii wide

    condition:
        any of them
}
