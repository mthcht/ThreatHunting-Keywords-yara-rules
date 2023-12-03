rule SharpRDP
{
    meta:
        description = "Detection patterns for the tool 'SharpRDP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRDP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string1 = /.{0,1000}\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\s\snla\=true.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string2 = /.{0,1000}\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\s\stakeover\=true.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string3 = /.{0,1000}\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sconnectdrive\=true.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string4 = /.{0,1000}\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=taskmgr.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string5 = /.{0,1000}\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=winr.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string6 = /.{0,1000}\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sexec\=cmd.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string7 = /.{0,1000}\/SharpRDP\.git.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string8 = /.{0,1000}0xthirteen\/SharpRDP.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string9 = /.{0,1000}SharpRDP\..{0,1000}\.dll\.bin.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string10 = /.{0,1000}SharpRDP\.csproj.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string11 = /.{0,1000}SharpRDP\.exe.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string12 = /.{0,1000}SharpRDP\.sln.{0,1000}/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string13 = /.{0,1000}SharpRDP\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
