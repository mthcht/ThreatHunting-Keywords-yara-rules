rule WINspect
{
    meta:
        description = "Detection patterns for the tool 'WINspect' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WINspect"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WINspect is part of a larger project for auditing different areas of Windows environments.It focuses on enumerating different parts of a Windows machine to identify security weaknesses and point to components that need further hardening.can be used by attacker 
        // Reference: https://github.com/A-mIn3/WINspect
        $string1 = /WINspect\.ps1/ nocase ascii wide

    condition:
        any of them
}
