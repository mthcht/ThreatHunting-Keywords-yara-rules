rule JuicyPotatoNG
{
    meta:
        description = "Detection patterns for the tool 'JuicyPotatoNG' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JuicyPotatoNG"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string1 = /\.exe\s\-l\s.*\s\-c\s{B91D5831\-B1BD\-4608\-8198\-D72E155020F7}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string2 = /\.exe\s\-l\s.*\s\-c\s{F7FD3FD6\-9994\-452D\-8DA7\-9A8FD87AEEF4}\s\-a/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string3 = /\/JuicyPotatoNG\.git/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string4 = /\\JuicyPotatoNG/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string5 = /261f880e\-4bee\-428d\-9f64\-c29292002c19/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string6 = /antonioCoco\/JuicyPotatoNG/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string7 = /BruteforceCLSIDs\./ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string8 = /C73A4893\-A5D1\-44C8\-900C\-7B8850BBD2EC/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string9 = /JuicyPotatoNG\.cpp/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string10 = /JuicyPotatoNG\.exe/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string11 = /JuicyPotatoNG\.sln/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string12 = /JuicyPotatoNG\.txt/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string13 = /JuicyPotatoNG\-main/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string14 = /PotatoTrigger\.cpp/ nocase ascii wide

    condition:
        any of them
}