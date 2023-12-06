rule SharpClipHistory
{
    meta:
        description = "Detection patterns for the tool 'SharpClipHistory' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpClipHistory"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpClipHistory is a .NET 4.5 application written in C# that can be used to read the contents of a users clipboard history in Windows 10 starting from the 1809 Build.
        // Reference: https://github.com/FSecureLABS/SharpClipHistory
        $string1 = /SharpClipHistory/ nocase ascii wide

    condition:
        any of them
}
