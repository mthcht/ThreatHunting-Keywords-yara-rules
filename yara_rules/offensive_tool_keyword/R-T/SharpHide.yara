rule SharpHide
{
    meta:
        description = "Detection patterns for the tool 'SharpHide' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpHide"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string1 = /.{0,1000}\/SharpHide\.git.{0,1000}/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string2 = /.{0,1000}443D8CBF\-899C\-4C22\-B4F6\-B7AC202D4E37.{0,1000}/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string3 = /.{0,1000}outflanknl\/SharpHide.{0,1000}/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string4 = /.{0,1000}SharpHide\.csproj.{0,1000}/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string5 = /.{0,1000}SharpHide\.exe.{0,1000}/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string6 = /.{0,1000}SharpHide\.sln.{0,1000}/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string7 = /.{0,1000}SharpHide\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
