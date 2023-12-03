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
        $string1 = /.{0,1000}\/WerTrigger\.git.{0,1000}/ nocase ascii wide
        // Description: Weaponizing for privileged file writes bugs with windows problem reporting
        // Reference: https://github.com/sailay1996/WerTrigger
        $string2 = /.{0,1000}WerTrigger\.exe.{0,1000}/ nocase ascii wide
        // Description: Weaponizing for privileged file writes bugs with windows problem reporting
        // Reference: https://github.com/sailay1996/WerTrigger
        $string3 = /.{0,1000}WerTrigger\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
