rule micr0_shell
{
    meta:
        description = "Detection patterns for the tool 'micr0_shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "micr0_shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string1 = /\s\-\-execution\sfalse\s\-\-save\sTrue\s\-\-output\s.{0,100}\.bin/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string2 = /\s\-\-ip\s.{0,100}\s\-\-port\s.{0,100}\s\-\-type\scmd\s\-\-language\s/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string3 = /\s\-\-ip\s.{0,100}\s\-\-variable\sshellcode\s/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string4 = /\/micr0\%20shell\.py/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string5 = /\/micr0_shell\.git/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string6 = /micr0\sshell\.py/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string7 = /micr0_shell\-main/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string8 = /micr0shell\.py\s/ nocase ascii wide
        // Description: micr0shell is a Python script that dynamically generates Windows X64 PIC Null-Free reverse shell shellcode.
        // Reference: https://github.com/senzee1984/micr0_shell
        $string9 = /senzee1984\/micr0_shell/ nocase ascii wide
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
