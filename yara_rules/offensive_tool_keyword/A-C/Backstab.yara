rule Backstab
{
    meta:
        description = "Detection patterns for the tool 'Backstab' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Backstab"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string1 = /\/Backstab\.git/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string2 = /\/Backstab\/Backstab/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string3 = /\/resources\/PROCEXP\.sys/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string4 = /\\resources\\PROCEXP\.sys/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string5 = /A0E7B538\-F719\-47B8\-8BE4\-A82C933F5753/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string6 = /backstab\.exe/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string7 = /Backstab\.sln/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string8 = /Backstab\/Driverloading/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string9 = /Backstab\-master/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string10 = /Yaxser\/Backstab/ nocase ascii wide

    condition:
        any of them
}
