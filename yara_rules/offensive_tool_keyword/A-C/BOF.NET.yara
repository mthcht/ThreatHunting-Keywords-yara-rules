rule BOF_NET
{
    meta:
        description = "Detection patterns for the tool 'BOF.NET' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BOF.NET"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string1 = /.{0,1000}BOF\.NET\.git.{0,1000}/ nocase ascii wide
        // Description: A .NET Runtime for Cobalt Strike's Beacon Object Files
        // Reference: https://github.com/CCob/BOF.NET
        $string2 = /.{0,1000}BOF\.NET\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
