rule fltMC
{
    meta:
        description = "Detection patterns for the tool 'fltMC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fltMC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Unload Sysmon driver. allow the attacker to bypass sysmon detections (most of it. network monitoring will still be effective)
        // Reference: https://github.com/mthcht/Purpleteam/blob/main/Simulation/Windows/System/unload_sysmon_driver_with_fltmc.ps1
        $string1 = /fltMC.{0,1000}\sunload\sSysmonDrv/ nocase ascii wide

    condition:
        any of them
}
