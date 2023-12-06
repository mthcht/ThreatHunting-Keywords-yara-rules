rule Passware_Kit_Forensic
{
    meta:
        description = "Detection patterns for the tool 'Passware Kit Forensic' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Passware Kit Forensic"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Passware Kit Forensic is the complete encrypted electronic evidence discovery solution that reports and decrypts all password-protected items on a computer
        // Reference: https://www.passware.com/kit-forensic/
        $string1 = /passware\-kit\-forensic\.sls/ nocase ascii wide
        // Description: Passware Kit Forensic is the complete encrypted electronic evidence discovery solution that reports and decrypts all password-protected items on a computer
        // Reference: https://www.passware.com/kit-forensic/
        $string2 = /PasswareKitForensic_.{0,1000}_Setup\.dmg/ nocase ascii wide
        // Description: Passware Kit Forensic is the complete encrypted electronic evidence discovery solution that reports and decrypts all password-protected items on a computer
        // Reference: https://www.passware.com/kit-forensic/
        $string3 = /PasswareKitForensic_.{0,1000}_Setup\.msi/ nocase ascii wide
        // Description: Passware Kit Forensic is the complete encrypted electronic evidence discovery solution that reports and decrypts all password-protected items on a computer
        // Reference: https://www.passware.com/kit-forensic/
        $string4 = /passware\-kit\-forensic\-64bit\.msi/ nocase ascii wide

    condition:
        any of them
}
