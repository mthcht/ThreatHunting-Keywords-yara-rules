rule VBA_RunPE
{
    meta:
        description = "Detection patterns for the tool 'VBA-RunPE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VBA-RunPE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple yet effective implementation of the RunPE technique in VBA. This code can be used to run executables from the memory of Word or Excel. It is compatible with both 32 bits and 64 bits versions of Microsoft Office 2010 and above.
        // Reference: https://github.com/itm4n/VBA-RunPE
        $string1 = /VBA\-RunPE\s\-/ nocase ascii wide

    condition:
        any of them
}
