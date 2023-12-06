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
        $string1 = /\/SMShell\.git/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string2 = /\/SMShell\// nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string3 = /\-\-mifi\-username\s.{0,1000}\s\-\-mifi\-password\s.{0,1000}\s\-\-number\s\+/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string4 = /persistent\-security\/SMShell/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string5 = /server\-console\.exe\s\+/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string6 = /server\-console\.py\s\-\-mifi\-ip\s/ nocase ascii wide
        // Description: PoC for a SMS-based shell. Send commands and receive responses over SMS from mobile broadband capable computers
        // Reference: https://github.com/persistent-security/SMShell
        $string7 = /SMShell\.sln/ nocase ascii wide

    condition:
        any of them
}
