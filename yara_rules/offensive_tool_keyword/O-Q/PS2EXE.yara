rule PS2EXE
{
    meta:
        description = "Detection patterns for the tool 'PS2EXE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PS2EXE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string1 = /\/PS2EXE\.git/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string2 = /\/PS2EXE\// nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string3 = /\\Win\-PS2EXE/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string4 = /Install\-Module\sps2exe/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string5 = /Invoke\-ps2exe/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string6 = /MScholtes\/PS2EXE/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string7 = /ps2exe\s\-/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string8 = /ps2exe\s.{0,1000}\.ps1.{0,1000}\.exe/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string9 = /ps2exe\.ps1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string10 = /ps2exe\.psd1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string11 = /ps2exe\.psm1/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string12 = /PS2EXE\-master/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string13 = /Win\-PS2EXE\.exe/ nocase ascii wide

    condition:
        any of them
}
