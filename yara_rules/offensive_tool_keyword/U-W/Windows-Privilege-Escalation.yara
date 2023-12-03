rule Windows_Privilege_Escalation
{
    meta:
        description = "Detection patterns for the tool 'Windows-Privilege-Escalation' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Windows-Privilege-Escalation"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string1 = /.{0,1000}\\Users\\Public\\nc\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string2 = /.{0,1000}CopyAndPasteEnum\.bat.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string3 = /.{0,1000}CopyAndPasteFileDownloader\.bat.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string4 = /.{0,1000}cscript\sdl\.vbs\s.{0,1000}http.{0,1000}\/.{0,1000}\.zip.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string5 = /.{0,1000}ReverseShell\.ps1.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string6 = /.{0,1000}windows_recon\.bat.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string7 = /.{0,1000}windows\-privesc\-check.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string8 = /.{0,1000}Windows\-Privilege\-Escalation.{0,1000}/ nocase ascii wide
        // Description: Windows Privilege Escalation Techniques and Scripts
        // Reference: https://github.com/frizb/Windows-Privilege-Escalation
        $string9 = /.{0,1000}winreconstreamline\.bat.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
