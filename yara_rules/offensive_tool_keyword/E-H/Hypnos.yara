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
        $string1 = /.{0,1000}\/Hypnos\.git.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string2 = /.{0,1000}\\Hypnos\.exe.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string3 = /.{0,1000}\\Hypnos\.sln.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string4 = /.{0,1000}\\Hypnos\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string5 = /.{0,1000}\\Hypnos\-main\\.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string6 = /.{0,1000}CaptainNox\/Hypnos.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string7 = /.{0,1000}D210570B\-F1A0\-4B66\-9301\-F7A54978C178.{0,1000}/ nocase ascii wide
        // Description: indirect syscalls - the Win API functions are not hooked by AV/EDR - bypass EDR detections
        // Reference: https://github.com/CaptainNox/Hypnos
        $string8 = /.{0,1000}Hypnos\-main\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
