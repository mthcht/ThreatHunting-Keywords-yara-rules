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
        $string1 = /.{0,1000}\/NPPSPY\.dll.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string2 = /.{0,1000}\/NPPSpy\.exe.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string3 = /.{0,1000}\/PSPY\.dll.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string4 = /.{0,1000}\\NPPSpy\.c.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string5 = /.{0,1000}\\NPPSPY\.dll.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string6 = /.{0,1000}\\NPPSpy\.exe.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string7 = /.{0,1000}\\NPPSpy\.txt.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string8 = /.{0,1000}\\PSPY\.dll.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string9 = /.{0,1000}\\PSPY\.exe.{0,1000}/ nocase ascii wide
        // Description: Simple code for NPLogonNotify(). The function obtains logon data including cleartext password
        // Reference: https://github.com/gtworek/PSBits/blob/master/PasswordStealing/NPPSpy
        $string10 = /.{0,1000}\\StolenPasswords\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
