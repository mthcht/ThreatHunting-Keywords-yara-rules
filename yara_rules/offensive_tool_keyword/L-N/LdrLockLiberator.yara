rule LdrLockLiberator
{
    meta:
        description = "Detection patterns for the tool 'LdrLockLiberator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LdrLockLiberator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LdrLockLiberator is a collection of techniques for escaping or otherwise forgoing Loader Lock while executing your code from DllMain or anywhere else the lock may be present.
        // Reference: https://github.com/ElliotKillick/LdrLockLiberator
        $string1 = /\/LdrLockLiberator\.git/ nocase ascii wide
        // Description: LdrLockLiberator is a collection of techniques for escaping or otherwise forgoing Loader Lock while executing your code from DllMain or anywhere else the lock may be present.
        // Reference: https://github.com/ElliotKillick/LdrLockLiberator
        $string2 = /\\LdrLockLiberator\.c/ nocase ascii wide
        // Description: LdrLockLiberator is a collection of techniques for escaping or otherwise forgoing Loader Lock while executing your code from DllMain or anywhere else the lock may be present.
        // Reference: https://github.com/ElliotKillick/LdrLockLiberator
        $string3 = /\\LdrLockLiberatorWDK\.c/ nocase ascii wide
        // Description: LdrLockLiberator is a collection of techniques for escaping or otherwise forgoing Loader Lock while executing your code from DllMain or anywhere else the lock may be present.
        // Reference: https://github.com/ElliotKillick/LdrLockLiberator
        $string4 = /ElliotKillick\/LdrLockLiberator/ nocase ascii wide
        // Description: LdrLockLiberator is a collection of techniques for escaping or otherwise forgoing Loader Lock while executing your code from DllMain or anywhere else the lock may be present.
        // Reference: https://github.com/ElliotKillick/LdrLockLiberator
        $string5 = /LdrLockLiberator\-main/ nocase ascii wide

    condition:
        any of them
}
