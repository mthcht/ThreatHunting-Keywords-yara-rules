rule CelestialSpark
{
    meta:
        description = "Detection patterns for the tool 'CelestialSpark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CelestialSpark"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string1 = /\/\/\sA\:\sthe\sMeterpreter\sstage\sis\sa\slarge\sshellcode\s/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string2 = /\/\/\sDefine\sIP\sAdress\sof\syour\sC2\sStager\s\(\!\)/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string3 = /\/CelestialSpark\.git/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string4 = /\[\!\]\sFailed\sto\sload\sshellcode\sinto\smemory/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string5 = /\\asm_CelestialSpark\.x64\.o/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string6 = /\\loader\.x64\.exe/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string7 = /482002c785db1a3432ec214464a19042a3f36a21e5617a9901a0eae9f04451f1/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string8 = /b8c9caeda6743d224835019b8bdc0105ad54f9a804a33e7e51acb605a8e8bc25/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string9 = /Karkas66\/CelestialSpark/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string10 = /MessageBoxW\(.{0,1000}\"Stardust\sSocket\sFailed\"/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string11 = /MessageBoxW\(.{0,1000}\"Stardust\sSocket\sInitialization\"/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string12 = /MessageBoxW\(.{0,1000}\"We\sare\sall\smade\sof\sStardust\!\"/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string13 = /\'S\'\,\s\'T\'\,\s\'A\'\,\s\'R\'\,\s\'D\'\,\s\'U\'\,\s\'S\'\,\s\'T\'\,\s\'\-\'\,\s\'E\'\,\s\'N\'\,\s\'D\'/ nocase ascii wide
        // Description: A modern 64-bit position independent meterpreter and Sliver compatible reverse_TCP Staging Shellcode based on Cracked5piders Stardust
        // Reference: https://github.com/Karkas66/CelestialSpark
        $string14 = /x64\/CelestialSpark\.asm/ nocase ascii wide

    condition:
        any of them
}
