rule pysnaffler
{
    meta:
        description = "Detection patterns for the tool 'pysnaffler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pysnaffler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string1 = /\ssnaffler\.py\s/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string2 = /\.\/snaffler_downloads/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string3 = /\/pysnaffler\.git/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string4 = /\/snaffler\.py/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string5 = /\\pysnaffler\\pysnaffler\\/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string6 = /\\snaffler\.py/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string7 = /from\spysnaffler\.rules\.constants\simport\s/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string8 = /from\spysnaffler\.rules\.rule\simport\sSnaffleRule/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string9 = /from\spysnaffler\.ruleset\simport\sSnafflerRuleSet/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string10 = /from\spysnaffler\.scanner\simport\sSnafflerScanner/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string11 = /from\spysnaffler\.snaffler\simport\s/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string12 = /pysnaffler\s\-/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string13 = /pysnaffler\s\'smb2\+kerberos\+password\:/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string14 = /pysnaffler\s\'smb2\+ntlm\-nt\:\/\// nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string15 = /pysnaffler\s\'smb2\+ntlm\-password\:\/\// nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string16 = /pysnaffler\.whatif\:main/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string17 = /pysnaffler\/_version\.py/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string18 = /pysnaffler\-main/ nocase ascii wide
        // Description: This project is a Python version of the well-known Snaffler project. Not a full implementation of that project - only focusing on SMB share/dir/file enumeration and download and parse.
        // Reference: https://github.com/skelsec/pysnaffler
        $string19 = /skelsec\/pysnaffler/ nocase ascii wide
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
