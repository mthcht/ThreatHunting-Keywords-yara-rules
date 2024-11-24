rule PrivKit
{
    meta:
        description = "Detection patterns for the tool 'PrivKit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivKit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string1 = /\/PrivKit\.git/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string2 = "/PrivKit/" nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string3 = /\\modifiableautorun\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string4 = /\\PrivKit\\/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string5 = /\\tokenprivileges\.c/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string6 = /\\tokenprivileges\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string7 = /\\unquotedsvcpath\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string8 = /alwaysinstallelevated\.c/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string9 = /alwaysinstallelevated\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string10 = /\-c\scredentialmanager\.c\s\-o\scredentialmanager\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string11 = /\-c\smodifiableautorun\.c\s\-o\smodifiableautorun\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string12 = /\-c\stokenprivileges\.c\s\-o\stokenprivileges\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string13 = /\-c\sunquotedsvcpath\.c\s\-o\sunquotedsvcpath\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string14 = /hijackablepath\.c/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string15 = /hijackablepath\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string16 = /inline\-execute\s.{0,100}tokenprivileges\.o/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string17 = "Priv Esc Check Bof" nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string18 = /privcheck\.cna/ nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string19 = "privcheck32" nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string20 = "PrivKit32" nocase ascii wide
        // Description: PrivKit is a simple beacon object file that detects privilege escalation vulnerabilities caused by misconfigurations on Windows OS.
        // Reference: https://github.com/mertdas/PrivKit
        $string21 = "PrivKit-main" nocase ascii wide
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
