rule supershell
{
    meta:
        description = "Detection patterns for the tool 'supershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "supershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string1 = /\s\-a\s\-t\stitleFixed\=\'Supershell\s\-\sInject\'\s\-t\sdisableLeaveAlert\=true\s\-t\sdisableReconnect\=true\sssh\s\-J\srssh\:/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string2 = /\s\-a\s\-t\stitleFixed\=\'Supershell\s\-\sShell\'\s\-t\sdisableLeaveAlert\=true\sssh\s\-J\srssh\:/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string3 = /\sSupershell\.tar\.gz/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string4 = /\/flask\:5000\/supershell\// nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string5 = /\/Supershell\.tar\.gz/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string6 = /\/supershell\/login\/auth/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string7 = /\/Supershell\/releases/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string8 = /\\Supershell\.tar\.gz/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string9 = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string10 = /\\Supershell\\rssh\\pkg\\/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string11 = /b7671f125bb2ed21d0476a00cfaa9ed6/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string12 = /http\:\/\/shell\:7681\/token/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string13 = /password\s\=\s\'tdragon6\'/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string14 = /supershell.{0,100}winpty\.dll/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string15 = /supershell.{0,100}winpty\-agent\.exe/ nocase ascii wide
        // Description: Supershell is a C2 remote control platform accessed through WEB services. By establishing a reverse SSH tunnel it obtains a fully interactive Shell and supports multi-platform architecture Payload
        // Reference: https://github.com/tdragon6/Supershell
        $string16 = /tdragon6\/Supershell/ nocase ascii wide
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
