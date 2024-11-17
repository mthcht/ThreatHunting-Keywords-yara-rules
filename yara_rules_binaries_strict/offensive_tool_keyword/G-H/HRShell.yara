rule HRShell
{
    meta:
        description = "Detection patterns for the tool 'HRShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HRShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string1 = /\sclient\.py\s\-s\shttp.{0,100}\:5000\s\-\-cert\s\/.{0,100}\.pem/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string2 = /\sserver\.py\s\-s\stornado\s\-\-cert\s\/.{0,100}pem\s\-\-key\s\/.{0,100}\.pem/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string3 = /\/HRShell\.git/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string4 = /\/HRShell\// nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string5 = /\/meterpreter\/reverse_tcp/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string6 = /\/shellcodes\/utils\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string7 = /chrispetrou\/HRShell/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string8 = /exploit\s\-j\s\-z/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string9 = /from\sshellcodes\simport\s/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string10 = /history_cmd/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string11 = /HRShell.{0,100}client\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string12 = /HRShell.{0,100}server\.py/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string13 = /inject\sshellcode/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string14 = /set\sshellcode\s/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string15 = /set_shellcode/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string16 = /shellcode1\s\+\=\sb/ nocase ascii wide
        // Description: HRShell is an HTTPS/HTTP reverse shell built with flask. It is an advanced C2 server with many features & capabilities.
        // Reference: https://github.com/chrispetrou/HRShell
        $string17 = /set\sshellcode\s/ nocase ascii wide
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
