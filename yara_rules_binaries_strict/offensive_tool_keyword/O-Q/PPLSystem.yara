rule PPLSystem
{
    meta:
        description = "Detection patterns for the tool 'PPLSystem' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLSystem"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string1 = /\.exe\s\-\-dll\s.{0,100}\s\-\-dump\s.{0,100}\s\-\-pid\s/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string2 = /\/pplsystem\.exe/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string3 = /\/PPLSystem\.git/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string4 = /\[\+\]\sRemote\sCOM\ssecret\s\:\s/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string5 = /\\pplsystem\.exe/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string6 = /\\PPLSystem\-main/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string7 = "531870bd9f59ac799dfa6573472db1966cd3a9f8ece84d2f2e409e4384770b4a" nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string8 = /Live\sDump\sCapture\sDump\sData\sAPI\sended\.\sNT\sStatus\:\sSTATUS_SUCCESS\./ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string9 = /pplsystem\.exe\s/ nocase ascii wide
        // Description: creates a livedump of the machine through NtDebugSystemControl to extract the COM secret and context, to then inject inside this process.
        // Reference: https://github.com/Slowerzs/PPLSystem
        $string10 = "Slowerzs/PPLSystem" nocase ascii wide
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
