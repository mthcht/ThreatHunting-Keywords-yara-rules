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
        $string2 = /\/SharpHide\.git/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string3 = /\[\+\]\sSharpHide\srunning\sas\selevated\suser/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string4 = /\[\+\]\sSharpHide\srunning\sas\snormal\suser/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string5 = /\\Windows\\Temp\\Bla\.exe/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string6 = "443D8CBF-899C-4C22-B4F6-B7AC202D4E37" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string7 = "66504e8c044a01ed3ef2a97dd36de68b7b1913d737d6ad4e6bd7778d80dec92f" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string8 = "6ff0ec2a775575ab2724c254aa386c44155453c1ae020446a6fb5b0535de65d3" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string9 = "outflanknl/SharpHide" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string10 = "SharpHide running as elevated user" nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string11 = /SharpHide\.csproj/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string12 = /SharpHide\.exe/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string13 = /SharpHide\.sln/ nocase ascii wide
        // Description: Tool to create hidden registry keys
        // Reference: https://github.com/outflanknl/SharpHide
        $string14 = "SharpHide-master" nocase ascii wide

    condition:
        any of them
}
