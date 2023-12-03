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
        $string1 = /.{0,1000}\/Backstab\.git/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string2 = /.{0,1000}\/Backstab\/Backstab.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string3 = /.{0,1000}\/resources\/PROCEXP\.sys.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string4 = /.{0,1000}\\resources\\PROCEXP\.sys.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string5 = /.{0,1000}backstab\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string6 = /.{0,1000}Backstab\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string7 = /.{0,1000}Backstab\/Driverloading.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string8 = /.{0,1000}Backstab\-master.{0,1000}/ nocase ascii wide
        // Description: A tool to kill antimalware protected processes
        // Reference: https://github.com/Yaxser/Backstab
        $string9 = /.{0,1000}Yaxser\/Backstab.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
