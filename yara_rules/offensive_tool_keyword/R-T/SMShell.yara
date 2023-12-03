rule SMShell
{
    meta:
        description = "Detection patterns for the tool 'SMShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SMShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string1 = /.{0,1000}\/SMShell\.git.{0,1000}/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string2 = /.{0,1000}\/SMShell\/.{0,1000}/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string3 = /.{0,1000}\-\-mifi\-username\s.{0,1000}\s\-\-mifi\-password\s.{0,1000}\s\-\-number\s\+.{0,1000}/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string4 = /.{0,1000}persistent\-security\/SMShell.{0,1000}/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string5 = /.{0,1000}server\-console\.exe\s\+.{0,1000}/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string6 = /.{0,1000}server\-console\.py\s\-\-mifi\-ip\s.{0,1000}/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string7 = /.{0,1000}SMShell\.sln.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
