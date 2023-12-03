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
        $string1 = /.{0,1000}\.exe\s\-l\s.{0,1000}\s\-c\s{B91D5831\-B1BD\-4608\-8198\-D72E155020F7}.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string2 = /.{0,1000}\.exe\s\-l\s.{0,1000}\s\-c\s{F7FD3FD6\-9994\-452D\-8DA7\-9A8FD87AEEF4}\s\-a.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string3 = /.{0,1000}\/JuicyPotatoNG\.git.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string4 = /.{0,1000}\\JuicyPotatoNG.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string5 = /.{0,1000}261f880e\-4bee\-428d\-9f64\-c29292002c19.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string6 = /.{0,1000}antonioCoco\/JuicyPotatoNG.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string7 = /.{0,1000}BruteforceCLSIDs\..{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string8 = /.{0,1000}C73A4893\-A5D1\-44C8\-900C\-7B8850BBD2EC.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string9 = /.{0,1000}JuicyPotatoNG\.cpp.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string10 = /.{0,1000}JuicyPotatoNG\.exe.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string11 = /.{0,1000}JuicyPotatoNG\.sln.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string12 = /.{0,1000}JuicyPotatoNG\.txt.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string13 = /.{0,1000}JuicyPotatoNG\-main.{0,1000}/ nocase ascii wide
        // Description: Another Windows Local Privilege Escalation from Service Account to System
        // Reference: https://github.com/antonioCoco/JuicyPotatoNG
        $string14 = /.{0,1000}PotatoTrigger\.cpp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
