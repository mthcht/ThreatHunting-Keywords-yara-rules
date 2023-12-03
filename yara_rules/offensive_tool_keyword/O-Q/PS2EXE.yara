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
        $string1 = /.{0,1000}\/PS2EXE\.git.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string2 = /.{0,1000}\/PS2EXE\/.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string3 = /.{0,1000}\\Win\-PS2EXE.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string4 = /.{0,1000}Install\-Module\sps2exe.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string5 = /.{0,1000}Invoke\-ps2exe.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string6 = /.{0,1000}MScholtes\/PS2EXE.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string7 = /.{0,1000}ps2exe\s\-.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string8 = /.{0,1000}ps2exe\s.{0,1000}\.ps1.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string9 = /.{0,1000}ps2exe\.ps1.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string10 = /.{0,1000}ps2exe\.psd1.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string11 = /.{0,1000}ps2exe\.psm1.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string12 = /.{0,1000}PS2EXE\-master.{0,1000}/ nocase ascii wide
        // Description: Module to compile powershell scripts to executables
        // Reference: https://github.com/MScholtes/PS2EXE
        $string13 = /.{0,1000}Win\-PS2EXE\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
