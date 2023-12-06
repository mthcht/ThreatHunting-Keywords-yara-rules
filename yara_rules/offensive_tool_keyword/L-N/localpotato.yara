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
        $string1 = /\s\/potato\.local/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string2 = /\/evil\.dll/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string3 = /\/LocalPotato\.git/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string4 = /\/webdavshare\/potato\.local/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string5 = /\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string6 = /\\evil\.dll/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string7 = /1B3C96A3\-F698\-472B\-B786\-6FED7A205159/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string8 = /\-c\s854A20FB\-2D44\-457D\-992F\-EF13785D2B51/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string9 = /DCOMReflection\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string10 = /decoder\-it\/LocalPotato/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string11 = /IUnknownObj\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string12 = /localpotato\s\-i/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string13 = /LocalPotato\.cpp/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string14 = /LocalPotato\.exe/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string15 = /LocalPotato\.sln/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string16 = /LocalPotato\.vcxproj/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string17 = /LocalPotato\.zip/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string18 = /LocalPotato\-master/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string19 = /PotatoTrigger\.cpp/ nocase ascii wide

    condition:
        any of them
}
