rule win_brute_logon
{
    meta:
        description = "Detection patterns for the tool 'win-brute-logon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "win-brute-logon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string1 = /.{0,1000}\sdarkcodersc\s.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string2 = /.{0,1000}\/DarkCoderSc\/.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string3 = /.{0,1000}\/WinBruteLogon.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string4 = /.{0,1000}\/win\-brute\-logon.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string5 = /.{0,1000}net\suser\sHackMe\s.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string6 = /.{0,1000}WinBruteLogon.{0,1000}\s\-v\s\-u.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string7 = /.{0,1000}WinBruteLogon\.dpr.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string8 = /.{0,1000}WinBruteLogon\.dproj.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string9 = /.{0,1000}WinBruteLogon\.exe.{0,1000}/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string10 = /.{0,1000}WinBruteLogon\.res.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
