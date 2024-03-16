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
        $string1 = /\s\sExecute\scommand\selevated\sthrough\sRun\sDialog/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string2 = /\s\sExecute\scommand\selevated\sthrough\stask\smanager/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string3 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\s\snla\=true/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string4 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\s\stakeover\=true/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string5 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sconnectdrive\=true/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string6 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=taskmgr/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string7 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\selevated\=winr/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string8 = /\.exe\scomputername\=.{0,1000}\scommand\=.{0,1000}\susername\=.{0,1000}\spassword\=.{0,1000}\sexec\=cmd/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string9 = /\.WriteLine\(\"SharpRDP\"\)/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string10 = /\/SharpRDP\.git/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string11 = /\\SharpRDP\\/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string12 = /0xthirteen\/SharpRDP/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string13 = /Ask\sto\stake\sover\sRDP\ssession\sif\sanother\sused\sis\slogged\sin\s\(workstation\)/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string14 = /b4726b5d0aa21ed0f06326fcf2f9bd0c6171c76b610287a357710174f06dea52/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string15 = /F1DF1D0F\-FF86\-4106\-97A8\-F95AAF525C54/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string16 = /SharpRDP\..{0,1000}\.dll\.bin/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string17 = /SharpRDP\.csproj/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string18 = /SharpRDP\.exe/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string19 = /SharpRDP\.sln/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string20 = /SharpRDP\-master/ nocase ascii wide

    condition:
        any of them
}
