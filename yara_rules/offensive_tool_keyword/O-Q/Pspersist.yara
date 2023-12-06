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
        $string2 = /5A403F3C\-9136\-4B67\-A94E\-02D3BCD3162D/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string3 = /Pspersist\-main/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string4 = /PSprofile\.cpp/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string5 = /Start\sMenu\\Programs\\Startup\\Loader\.exe/ nocase ascii wide
        // Description: Dropping a powershell script at %HOMEPATH%\Documents\windowspowershell\ that contains the implant's path and whenever powershell process is created the implant will executed too.
        // Reference: https://github.com/TheD1rkMtr/Pspersist
        $string6 = /TheD1rkMtr\/Pspersist/ nocase ascii wide

    condition:
        any of them
}
