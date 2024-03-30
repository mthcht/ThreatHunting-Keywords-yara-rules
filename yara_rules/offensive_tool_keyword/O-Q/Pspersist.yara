rule Pspersist
{
    meta:
        description = "Detection patterns for the tool 'Pspersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Pspersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string1 = /\/PSpersist\.git/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string2 = /\\PSprofile\.exe/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string3 = /436b7f540f534a0ec1337cf82a76cb7727acda423132195f0c81560cdf75c438/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string4 = /58482e19d6376bbe0120289b6d39a35de15b68d00713f821ab0c7f28f85a31ee/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string5 = /5A403F3C\-9136\-4B67\-A94E\-02D3BCD3162D/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string6 = /Pspersist\-main/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string7 = /PSprofile\.cpp/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string8 = /Start\sMenu\\Programs\\Startup\\Loader\.exe/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string9 = /TheD1rkMtr\/Pspersist/ nocase ascii wide

    condition:
        any of them
}
