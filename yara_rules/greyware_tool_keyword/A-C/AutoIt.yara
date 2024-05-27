rule AutoIt
{
    meta:
        description = "Detection patterns for the tool 'AutoIt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AutoIt"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: starting autoit script and hiding it
        // Reference: https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2024-05-14-IOCs-for-DarkGate-activity.txt
        $string1 = /start\s\'AutoIt3\.exe\'\s\-a\s\'.{0,1000}\.a3x\'\;attrib\s\+h/ nocase ascii wide

    condition:
        any of them
}
