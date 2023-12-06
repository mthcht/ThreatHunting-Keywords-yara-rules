rule WerTrigger
{
    meta:
        description = "Detection patterns for the tool 'WerTrigger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WerTrigger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weaponizing for privileged file writes bugs with windows problem reporting
        // Reference: https://github.com/sailay1996/WerTrigger
        $string1 = /\/WerTrigger\.git/ nocase ascii wide
        // Description: Weaponizing for privileged file writes bugs with windows problem reporting
        // Reference: https://github.com/sailay1996/WerTrigger
        $string2 = /WerTrigger\.exe/ nocase ascii wide
        // Description: Weaponizing for privileged file writes bugs with windows problem reporting
        // Reference: https://github.com/sailay1996/WerTrigger
        $string3 = /WerTrigger\-master/ nocase ascii wide

    condition:
        any of them
}
