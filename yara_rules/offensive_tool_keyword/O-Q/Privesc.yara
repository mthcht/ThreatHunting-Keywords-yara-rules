rule Privesc
{
    meta:
        description = "Detection patterns for the tool 'Privesc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Privesc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string1 = /\sprivesc\.ps1/ nocase ascii wide
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string2 = /\/Privesc\.git/ nocase ascii wide
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string3 = /\/privesc\.ps1/ nocase ascii wide
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string4 = /\\privesc\.ps1/ nocase ascii wide
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string5 = /\\Privesc\-master/ nocase ascii wide
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string6 = /enjoiz\/Privesc/ nocase ascii wide
        // Description: Windows PowerShell script that finds misconfiguration issues which can lead to privilege escalation
        // Reference: https://github.com/enjoiz/Privesc
        $string7 = /Invoke\-Privesc/ nocase ascii wide

    condition:
        any of them
}
