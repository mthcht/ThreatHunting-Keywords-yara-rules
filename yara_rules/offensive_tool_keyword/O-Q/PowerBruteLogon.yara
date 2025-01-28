rule PowerBruteLogon
{
    meta:
        description = "Detection patterns for the tool 'PowerBruteLogon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBruteLogon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string1 = "/PowerBruteLogon" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string2 = /\\PowerBruteLogon/ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string3 = "3d686ba6d6985ff3febf3cd3d45cb5eb18eff45bfec74142865ded01f9c00503" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string4 = "4b23fd7b0179a37fe15bf38ea9ccb0202202d36dcaa882c58a66c1979d37e92c" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string5 = "5f8fdd73abce168e8b44db54ad203a66d4983d1fd2563bb5922c0aaef9abc4ea" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string6 = "75682eac28a36100019a0606879be2a615e6c221b212833b2eb9ab83f6360cd6" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string7 = "Invoke-BruteAvailableLogons" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string8 = "Invoke-BruteLogonAccount" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string9 = "Invoke-BruteLogonList" nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string10 = /PowerBruteLogon\./ nocase ascii wide
        // Description: Bruteforce cracking tool for windows users
        // Reference: https://github.com/DarkCoderSc/PowerBruteLogon
        $string11 = /PowerBruteLogon\.zip/ nocase ascii wide

    condition:
        any of them
}
