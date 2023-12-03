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
        $string1 = /.{0,1000}\s\/potato\.local.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string2 = /.{0,1000}\/evil\.dll.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string3 = /.{0,1000}\/LocalPotato\.git.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string4 = /.{0,1000}\/webdavshare\/potato\.local.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string5 = /.{0,1000}\[\+\]\sSMB\sreflected\sDCOM\sauthentication\ssucceeded\!.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string6 = /.{0,1000}\\evil\.dll.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string7 = /.{0,1000}1B3C96A3\-F698\-472B\-B786\-6FED7A205159.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string8 = /.{0,1000}\-c\s854A20FB\-2D44\-457D\-992F\-EF13785D2B51.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string9 = /.{0,1000}DCOMReflection\.cpp.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string10 = /.{0,1000}decoder\-it\/LocalPotato.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string11 = /.{0,1000}IUnknownObj\.cpp.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string12 = /.{0,1000}localpotato\s\-i.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string13 = /.{0,1000}LocalPotato\.cpp.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string14 = /.{0,1000}LocalPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string15 = /.{0,1000}LocalPotato\.sln.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string16 = /.{0,1000}LocalPotato\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string17 = /.{0,1000}LocalPotato\.zip.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string18 = /.{0,1000}LocalPotato\-master.{0,1000}/ nocase ascii wide
        // Description: The LocalPotato attack is a type of NTLM reflection attack that targets local authentication. This attack allows for arbitrary file read/write and elevation of privilege.
        // Reference: https://github.com/decoder-it/LocalPotato
        $string19 = /.{0,1000}PotatoTrigger\.cpp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
