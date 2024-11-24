rule defender_control
{
    meta:
        description = "Detection patterns for the tool 'defender-control' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "defender-control"
        rule_category = "signature_keyword"

    strings:
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string1 = /Application\.Hacktool\.DisableDefender\.F/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string2 = "HackTool:Win32/DefenderControl" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string3 = /PUA\.Win32\.DefenderControl/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string4 = /RiskWare\.DefenderControl/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string5 = /Win\.Tool\.Disabledefender/ nocase ascii wide

    condition:
        any of them
}
