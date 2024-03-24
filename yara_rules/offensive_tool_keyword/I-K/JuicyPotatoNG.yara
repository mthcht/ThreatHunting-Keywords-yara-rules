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
        $string1 = /\sJuicyPotatoNG/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string2 = /\.exe\s\-l\s.{0,1000}\s\-c\s\{B91D5831\-B1BD\-4608\-8198\-D72E155020F7\}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string3 = /\.exe\s\-l\s.{0,1000}\s\-c\s\{F7FD3FD6\-9994\-452D\-8DA7\-9A8FD87AEEF4\}\s\-a/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string4 = /\/JuicyPotatoNG\.git/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string5 = /\[\-\]\sExploit\sfailed\!\s/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string6 = /\[\+\]\sExploit\ssuccessful\!\s/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string7 = /\\JuicyPotatoNG/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string8 = /\]\sBruteforcing\s\%d\sCLSIDs/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string9 = /261f880e\-4bee\-428d\-9f64\-c29292002c19/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string10 = /antonioCoco\/JuicyPotatoNG/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string11 = /BruteforceCLSIDs\./ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string12 = /c5af796b44a3d3d09e184ef622ad002b8298696c2de139392fd35898f5073527/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string13 = /C73A4893\-A5D1\-44C8\-900C\-7B8850BBD2EC/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string14 = /JuicyPotatoNG\.cpp/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string15 = /JuicyPotatoNG\.exe/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string16 = /JuicyPotatoNG\.sln/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string17 = /JuicyPotatoNG\.txt/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string18 = /JuicyPotatoNG\.zip/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string19 = /JuicyPotatoNG\-main/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string20 = /PotatoTrigger\.cpp/ nocase ascii wide

    condition:
        any of them
}
