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
        $string1 = /\/SharpSpoolTrigger/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string2 = /\/SharpSystemTriggers/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string3 = /Midl2Bytes\.exe/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string4 = /SharpDcomTrigger\.exe/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string5 = /SharpEfsTriggeEfs\.exe/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string6 = /SharpSpoolTrigger\.exe/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string7 = /SharpSystemTriggers\.git/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string8 = /SharpSystemTriggers\.sln/ nocase ascii wide
        // Description: Collection of remote authentication triggers in C#
        // Reference: https://github.com/cube0x0/SharpSystemTriggers
        $string9 = /SharpSystemTriggers\-main/ nocase ascii wide

    condition:
        any of them
}
