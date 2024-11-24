rule BadPotato
{
    meta:
        description = "Detection patterns for the tool 'BadPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BadPotato"
        rule_category = "signature_keyword"

    strings:
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string1 = "ATK/BadPotato-A" nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string2 = /BadPotato\.Win32/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string3 = /HackTool\.BadPotato/ nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string4 = "HackTool/BadPotato" nocase ascii wide
        // Description: Windows Privilege Escalation Exploit BadPotato
        // Reference: https://github.com/BeichenDream/BadPotato
        $string5 = "HackTool:Win32/Badcastle!pz" nocase ascii wide

    condition:
        any of them
}
