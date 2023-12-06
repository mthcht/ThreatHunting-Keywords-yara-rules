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
        $string1 = /\sdarkcodersc\s/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string2 = /\/DarkCoderSc\// nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string3 = /\/WinBruteLogon/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string4 = /\/win\-brute\-logon/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string5 = /net\suser\sHackMe\s/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string6 = /WinBruteLogon.{0,1000}\s\-v\s\-u/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string7 = /WinBruteLogon\.dpr/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string8 = /WinBruteLogon\.dproj/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string9 = /WinBruteLogon\.exe/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/win-brute-logon
        $string10 = /WinBruteLogon\.res/ nocase ascii wide

    condition:
        any of them
}
