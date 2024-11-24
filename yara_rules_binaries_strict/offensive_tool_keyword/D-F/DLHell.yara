rule DLHell
{
    meta:
        description = "Detection patterns for the tool 'DLHell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DLHell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string1 = /\sDLHell\.py/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string2 = "## DLHell Main function" nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string3 = "#Dumps exported function from legit DLL using winedump" nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string4 = "#Removes previous hijacked dll" nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string5 = /\.py\s\s\-t\s.{0,100}\.tpe\s\-c\s.{0,100}\.exe.{0,100}\s\-remote\-lib\s.{0,100}\-remote\-target\s/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string6 = /\.py\s\-t\stemplate\.tpe\s\-c\s\'calc\.exe\'/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string7 = /\/DLHell\.git/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string8 = /\/DLHell\.py/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string9 = /\\DLHell\.py/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string10 = /\\DLHell\-main\\/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string11 = "Available ProgIDs and CLSIDs for DLL Hijacking:" nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string12 = /DLHell\sv2\.0/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string13 = /DLHell\.py\s\-/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string14 = "DLL Hell - DLL Proxifier/Hijacker" nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string15 = /dump_exported_functions\(library\,dll_orig\)/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string16 = "f47ae40fa2ba9ad689d59f8b755ea68e116c3dd603d6f985a7eff273ce0f381b" nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string17 = /impacket\.dcerpc\.v5/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string18 = /impacket\.smbconnection/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string19 = /kevin\.tellier\@synacktiv\.com/ nocase ascii wide
        // Description: Local & remote Windows DLL Proxying
        // Reference: https://github.com/synacktiv/DLHell
        $string20 = "synacktiv/DLHell" nocase ascii wide
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
