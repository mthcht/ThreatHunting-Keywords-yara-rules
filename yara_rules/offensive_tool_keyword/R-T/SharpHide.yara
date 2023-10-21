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
        $string1 = /\/SharpHide\.git/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string2 = /443D8CBF\-899C\-4C22\-B4F6\-B7AC202D4E37/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string3 = /outflanknl\/SharpHide/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string4 = /SharpHide\.csproj/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string5 = /SharpHide\.exe/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string6 = /SharpHide\.sln/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string7 = /SharpHide\-master/ nocase ascii wide

    condition:
        any of them
}