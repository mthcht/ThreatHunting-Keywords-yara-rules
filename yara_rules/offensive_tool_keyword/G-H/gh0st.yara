rule gh0st
{
    meta:
        description = "Detection patterns for the tool 'gh0st' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gh0st"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string1 = "\"Gh0st RAT Exception\"" nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string2 = /\/gh0st\.exe/ nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string3 = /\/gh0st\.git/ nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string4 = /\/svchost_console\.exe/ nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string5 = /\\gh0st\.exe/ nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string6 = /\\svchost_console\.exe/ nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string7 = "0228336A-2F4C-0D17-2E11-86654A1FAD8D" nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string8 = "64D26B66-8A59-0724-007F-9001C4F472A2" nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string9 = "80ABA1A7-0E3E-3DB2-8EB9-D4EE1C266504" nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string10 = "91283687ba9f56c07f0664807a9387edd6f40e50607fc3c757bcd34b28eb1cd8" nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string11 = /kstowell\@codejockeys\.com/ nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string12 = "sin5678/gh0st" nocase ascii wide
        // Description: Malware RAT with keylogger - dll injection - C2 - Remote control
        // Reference: https://github.com/sin5678/gh0st
        $string13 = /wolfexp\.net\/other\/Gh0st_RAT\/demo\.rar/ nocase ascii wide

    condition:
        any of them
}
