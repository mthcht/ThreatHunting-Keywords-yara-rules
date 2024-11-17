rule ConPtyShell
{
    meta:
        description = "Detection patterns for the tool 'ConPtyShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ConPtyShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string1 = /\sConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string2 = /\$parametersConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string3 = /\/ConPtyShell\// nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string4 = /376713183026ccc822e9c1dead28cc81c7cfa7ad1c88e368ada6c31ce3909a2e/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string5 = /antonioCoco\/ConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string6 = /ConPtyShell\.cs/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string7 = /ConPtyShell\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string8 = /ConPtyShell\.git/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string9 = /ConPtyShell\.zip/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string10 = /ConPtyShell\.zip/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string11 = /ConPtyShell_dotnet2\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string12 = /CreatePseudoConsole\sfunction\sfound\!\sSpawning\sa\sfully\sinteractive\sshell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string13 = /CreatePseudoConsole\sfunction\snot\sfound\!\sSpawning\sa\snetcat\-like\sinteractive\sshell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string14 = /Invoke\-ConPtyShell/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string15 = /Invoke\-ConPtyShell\.ps1/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string16 = /\-RemoteIp\s.{0,100}\s\-RemotePort\s.{0,100}\s\-Rows\s.{0,100}\s\-Cols\s.{0,100}\s\-CommandLine\s.{0,100}\.exe/ nocase ascii wide
        // Description: ConPtyShell - Fully Interactive Reverse Shell for Windows
        // Reference: https://github.com/antonioCoco/ConPtyShell
        $string17 = /SocketHijacking\./ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
