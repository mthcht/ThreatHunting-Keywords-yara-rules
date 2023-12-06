rule NPPSpy
{
    meta:
        description = "Detection patterns for the tool 'NPPSpy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NPPSpy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string1 = /\/NPPSPY\.dll/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string2 = /\/NPPSpy\.exe/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string3 = /\/PSPY\.dll/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string4 = /\\NPPSpy\.c/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string5 = /\\NPPSPY\.dll/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string6 = /\\NPPSpy\.exe/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string7 = /\\NPPSpy\.txt/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string8 = /\\PSPY\.dll/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string9 = /\\PSPY\.exe/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string10 = /\\StolenPasswords\.txt/ nocase ascii wide

    condition:
        any of them
}
