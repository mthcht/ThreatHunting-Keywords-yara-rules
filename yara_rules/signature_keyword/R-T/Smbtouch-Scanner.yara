rule Smbtouch_Scanner
{
    meta:
        description = "Detection patterns for the tool 'Smbtouch-Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Smbtouch-Scanner"
        rule_category = "signature_keyword"

    strings:
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string1 = /HackTool\.Equation/ nocase ascii wide
        // Description: Smbtouch detect whether the target is vulnerable of one of these vulnerabilities: ETERNALBLUE - ETERNALCHAMPION - ETERNALROMANCE - ETERNALSYNERGY
        // Reference: https://github.com/3gstudent/Smbtouch-Scanner
        $string2 = /Trojan\:Win32\/Eqtonex\!rfn/ nocase ascii wide

    condition:
        any of them
}
