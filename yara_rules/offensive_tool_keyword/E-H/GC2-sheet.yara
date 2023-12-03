rule GC2_sheet
{
    meta:
        description = "Detection patterns for the tool 'GC2-sheet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GC2-sheet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string1 = /.{0,1000}\sGC2\-sheet.{0,1000}/ nocase ascii wide
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string2 = /.{0,1000}\/C2\/c2\.go.{0,1000}/ nocase ascii wide
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string3 = /.{0,1000}\/GC2\-sheet\/.{0,1000}/ nocase ascii wide
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string4 = /.{0,1000}\/internal\/C2\/.{0,1000}\.go.{0,1000}/ nocase ascii wide
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string5 = /.{0,1000}gc2\-sheet\.go.{0,1000}/ nocase ascii wide
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string6 = /.{0,1000}GC2\-sheet\/cmd.{0,1000}/ nocase ascii wide
        // Description: GC2 is a Command and Control application that allows an attacker to execute commands on the target machine using Google Sheet and exfiltrate data using Google Drive.
        // Reference: https://github.com/looCiprian/GC2-sheet
        $string7 = /.{0,1000}looCiprian\/GC2\-sheet.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
