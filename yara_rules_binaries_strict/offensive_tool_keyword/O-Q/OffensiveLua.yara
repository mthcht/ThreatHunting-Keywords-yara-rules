rule OffensiveLua
{
    meta:
        description = "Detection patterns for the tool 'OffensiveLua' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OffensiveLua"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string1 = /\sc\:\\\\Temp\\\\lua\.log/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string2 = /\/bin2hex\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string3 = /\/bindshell\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string4 = /\/downloadexec\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string5 = /\/OffensiveLua\.git/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string6 = /\/regread\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string7 = /\/regwrite\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string8 = /\/regwritedel\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string9 = /\/runcmd\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string10 = /\/runcmd2\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string11 = /\/runswhide\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string12 = /\\\\Users\\\\Fantastic\\\\Desktop\\\\DEMO\\\\plugins\\\\scripts\\\\/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string13 = /\\bin2hex\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string14 = /\\bindshell\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string15 = /\\downloadexec\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string16 = /\\luajit\.exe/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string17 = /\\regread\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string18 = /\\regwrite\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string19 = /\\regwritedel\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string20 = /\\runcmd\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string21 = /\\runcmd2\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string22 = /\\runswhide\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string23 = /\\x4d\\x5a\\x90\\x00\\x03\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\xff\\xff\\x00\\x00\\xb8\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xf8\\x00\\x00\\x00\\x0e\\x1f\\xba\\x0e\\x00\\xb4\\x09\\xcd\\x21\\xb8\\x01\\x4c\\xcd\\x21\\x54\\x68\\x69\\x73\\x20\\x70\\x72/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string24 = /C\:\\\\temp\\\\test\.txt/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string25 = /ComputerDefaultsUACBypass\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string26 = /copy\sTsutsuji_x64\.dll\s\%appdata\%.{0,100}Local\\Microsoft\\WindowsApps\\BluetoothDiagnosticUtil\.dll/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string27 = /downloadexec_UACbypass\.lua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string28 = /hackerhouse\-opensource\/OffensiveLua/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string29 = /http\:\/\/127\.0\.0\.1\/Renge_x64\.exe/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string30 = /OffensiveLua\-main/ nocase ascii wide
        // Description: Offensive Lua is a collection of offensive security scripts written in Lua with FFI
        // Reference: https://github.com/hackerhouse-opensource/OffensiveLua
        $string31 = /uac_bypass_bluetooth_win10\.lua/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
