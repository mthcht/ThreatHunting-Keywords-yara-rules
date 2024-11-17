rule LocalShellExtParse
{
    meta:
        description = "Detection patterns for the tool 'LocalShellExtParse' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LocalShellExtParse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string1 = /\sLocalShellExtParse\.py/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string2 = /\.py\s\-\-cached\s\-\-ntuser\sNTUSER\.DAT/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string3 = /\.py\s\-\-ntuser\sNTUSER\.DAT\s\-\-usrclass\sUsrClass\.dat/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string4 = /\/LocalShellExtParse\.git/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string5 = /\/LocalShellExtParse\.py/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string6 = /\\LocalShellExtParse\.py/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string7 = /\\LocalShellExtParse\-master/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string8 = /c3a499f047b670e888a41b33749ffc9227b7b0bcc4e9f0882d272918ee3a17d1/ nocase ascii wide
        // Description: Script to parse first load time for Shell Extensions loaded by user. Also enumerates all loaded Shell Extensions that are only installed for the Current User.
        // Reference: https://github.com/herrcore/LocalShellExtParse
        $string9 = /herrcore\/LocalShellExtParse/ nocase ascii wide
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
