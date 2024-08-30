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
        $string3 = /\/Backstab64\.exe/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string4 = /\/resources\/PROCEXP\.sys/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string5 = /\\Backstab\.sln/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string6 = /\\Backstab64\.exe/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string7 = /\\resources\\PROCEXP\.sys/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string8 = /268cd1727a2d84acc991768b9d4d30adcef18dca75f357e56aa0bdc91f345fd7/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string9 = /307eb30c7d3640ca11f564b1dbbb7a133236c3c9b45192ddcb317477a9f54b59/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string10 = /9678bdc0acce5aac06e4154631a01a94bfa9c2455efb5e72c3d8cdbf2663b019/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string11 = /A0E7B538\-F719\-47B8\-8BE4\-A82C933F5753/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string12 = /backstab\.exe/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string13 = /Backstab\.sln/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string14 = /Backstab\/Driverloading/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string15 = /Backstab\-master/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string16 = /bff5c33032fc4d1a25a3a569e72910b2dc500caf44b0d0baac16c4abd3868998/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string17 = /Yaxser\/Backstab/ nocase ascii wide

    condition:
        any of them
}
