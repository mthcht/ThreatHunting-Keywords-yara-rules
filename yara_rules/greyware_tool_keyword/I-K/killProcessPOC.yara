rule killProcessPOC
{
    meta:
        description = "Detection patterns for the tool 'killProcessPOC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "killProcessPOC"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string1 = /\/killProcessPOC\.git/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string2 = /\\\\\\\\\.\\\\aswSP_ArPot0/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string3 = /\\\\\\\\\.\\\\aswSP_ArPot1/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string4 = /\\\\\\\\\.\\\\aswSP_ArPot2/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string5 = /\\\\\\\\\.\\\\aswSP_ArPot3/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string6 = /\\\\\\\\\.\\\\aswSP_Avar/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string7 = /\\killProcessPOC/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string8 = /55ab03a0f7e3ce2c13664db76e5e0b6768cb66d88971b6bc6caf577831a77a23/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string9 = /sc\.exe\screate\saswSP_ArPot1/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string10 = /sc\.exe\screate\saswSP_ArPot2/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string11 = /sc\.exe\screate\saswSP_ArPot3/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string12 = /sc\.exe\screate\saswSP_ArPots/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string13 = /sc\.exe\sstart\saswSP_ArPot/ nocase ascii wide
        // Description: use  Avast (aswArPot.sys) to kill process - exploited by MONTI ransomware
        // Reference: https://github.com/timwhitez/killProcessPOC
        $string14 = /timwhitez\/killProcessPOC/ nocase ascii wide

    condition:
        any of them
}
