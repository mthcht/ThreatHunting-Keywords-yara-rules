rule sharphound
{
    meta:
        description = "Detection patterns for the tool 'sharphound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sharphound"
        rule_category = "signature_keyword"

    strings:
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string1 = /3f31295f3435ec6223bbd70a6c0d4620a344e2232c7255dd8fa84ed48aa7a59a/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string2 = /ATK\/BloodH\-B/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string3 = /HackTool\.MSIL\.SharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string4 = /Hacktool\.SharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string5 = /HackTool\:W32\/SharpHound/ nocase ascii wide
        // Description: C# Data Collector for BloodHound
        // Reference: https://github.com/BloodHoundAD/SharpHound
        $string6 = /Trojan\:Win32\/Sabsik\.TE\.B\!ml/ nocase ascii wide

    condition:
        any of them
}
