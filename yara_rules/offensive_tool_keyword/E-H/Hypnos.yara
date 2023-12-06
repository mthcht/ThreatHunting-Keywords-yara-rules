rule Hypnos
{
    meta:
        description = "Detection patterns for the tool 'Hypnos' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Hypnos"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string1 = /\/Hypnos\.git/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string2 = /\\Hypnos\.exe/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string3 = /\\Hypnos\.sln/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string4 = /\\Hypnos\.vcxproj/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string5 = /\\Hypnos\-main\\/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string6 = /CaptainNox\/Hypnos/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string7 = /D210570B\-F1A0\-4B66\-9301\-F7A54978C178/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string8 = /Hypnos\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
