rule SharpSystemTriggers
{
    meta:
        description = "Detection patterns for the tool 'SharpSystemTriggers' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSystemTriggers"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string1 = /.{0,1000}\/SharpSpoolTrigger.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string2 = /.{0,1000}\/SharpSystemTriggers.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string3 = /.{0,1000}Midl2Bytes\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string4 = /.{0,1000}SharpDcomTrigger\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string5 = /.{0,1000}SharpEfsTriggeEfs\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string6 = /.{0,1000}SharpSpoolTrigger\.exe.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string7 = /.{0,1000}SharpSystemTriggers\.git.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string8 = /.{0,1000}SharpSystemTriggers\.sln.{0,1000}/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string9 = /.{0,1000}SharpSystemTriggers\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
