rule dll_hijack_by_proxying
{
    meta:
        description = "Detection patterns for the tool 'dll-hijack-by-proxying' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dll-hijack-by-proxying"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string1 = "// Malicious payload should be implemented here" nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string2 = /\/dll\-hijack\-by\-proxying\.git/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string3 = /\\dll\-hijack\-by\-proxying/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string4 = /\\dll\-hijack\-by\-proxying\-master/ nocase ascii wide
        // Description: Exploiting DLL Hijacking by DLL Proxying Super Easily
        // Reference: https://github.com/tothi/dll-hijack-by-proxying
        $string5 = "tothi/dll-hijack-by-proxying" nocase ascii wide
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
