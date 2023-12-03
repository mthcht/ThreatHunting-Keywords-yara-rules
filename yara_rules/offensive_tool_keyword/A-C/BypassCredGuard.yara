rule BypassCredGuard
{
    meta:
        description = "Detection patterns for the tool 'BypassCredGuard' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BypassCredGuard"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string1 = /.{0,1000}\/BypassCredGuard\.git.{0,1000}/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string2 = /.{0,1000}BypassCredGuard\..{0,1000}/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string3 = /.{0,1000}BypassCredGuard\-master.{0,1000}/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string4 = /.{0,1000}F1527C49\-CA1F\-4994\-BB9D\-E20DD2C607FD.{0,1000}/ nocase ascii wide
        // Description: Credential Guard Bypass Via Patching Wdigest Memory
        // Reference: https://github.com/wh0amitz/BypassCredGuard
        $string5 = /.{0,1000}wh0amitz\/BypassCredGuard.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
