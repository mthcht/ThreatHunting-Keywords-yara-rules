rule localpotato
{
    meta:
        description = "Detection patterns for the tool 'localpotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localpotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string1 = /\/evil\.dll/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string2 = /\/LocalPotato\.git/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string3 = /\\evil\.dll/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string4 = /\-c\s854A20FB\-2D44\-457D\-992F\-EF13785D2B51/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string5 = /DCOMReflection\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string6 = /decoder\-it\/LocalPotato/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string7 = /IUnknownObj\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string8 = /localpotato\s\-i/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string9 = /LocalPotato\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string10 = /LocalPotato\.exe/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string11 = /LocalPotato\.sln/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string12 = /LocalPotato\.vcxproj/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string13 = /LocalPotato\.zip/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string14 = /LocalPotato\-master/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string15 = /PotatoTrigger\.cpp/ nocase ascii wide

    condition:
        any of them
}