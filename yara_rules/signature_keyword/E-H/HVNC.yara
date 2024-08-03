rule HVNC
{
    meta:
        description = "Detection patterns for the tool 'HVNC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HVNC"
        rule_category = "signature_keyword"

    strings:
        // Description: Standalone HVNC Client & Server Coded in C++ (Modified Tinynuke)
        // Reference: https://github.com/Meltedd/HVNC
        $string1 = /TrojanSpy\:Win32\/Tinukebot/ nocase ascii wide

    condition:
        any of them
}
