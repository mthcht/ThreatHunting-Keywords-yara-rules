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
        $string1 = /\.exe\scomputername\=.*\scommand\=.*\susername\=.*\spassword\=.*\s\snla\=true/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string2 = /\.exe\scomputername\=.*\scommand\=.*\susername\=.*\spassword\=.*\s\stakeover\=true/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string3 = /\.exe\scomputername\=.*\scommand\=.*\susername\=.*\spassword\=.*\sconnectdrive\=true/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string4 = /\.exe\scomputername\=.*\scommand\=.*\susername\=.*\spassword\=.*\selevated\=taskmgr/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string5 = /\.exe\scomputername\=.*\scommand\=.*\susername\=.*\spassword\=.*\selevated\=winr/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string6 = /\.exe\scomputername\=.*\scommand\=.*\susername\=.*\spassword\=.*\sexec\=cmd/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string7 = /\/SharpRDP\.git/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string8 = /0xthirteen\/SharpRDP/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string9 = /SharpRDP\..*\.dll\.bin/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string10 = /SharpRDP\.csproj/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string11 = /SharpRDP\.exe/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string12 = /SharpRDP\.sln/ nocase ascii wide
        // Description: Remote Desktop Protocol .NET Console Application for Authenticated Command Execution
        // Reference: https://github.com/0xthirteen/SharpRDP
        $string13 = /SharpRDP\-master/ nocase ascii wide

    condition:
        any of them
}