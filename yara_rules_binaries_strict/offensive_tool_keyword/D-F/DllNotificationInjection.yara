rule DllNotificationInjection
{
    meta:
        description = "Detection patterns for the tool 'DllNotificationInjection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DllNotificationInjection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string1 = /\/DllNotificationInjection\.git/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string2 = "0A1C2C46-33F7-4D4C-B8C6-1FC9B116A6DF" nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string3 = /DllNotificationInjection\.cpp/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string4 = /DllNotificationInjection\.exe/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string5 = /DllNotificationInjection\.sln/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string6 = /DllNotificationInjection\.vcxproj/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string7 = "DllNotificationInjection-master" nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string8 = /ShellcodeTemplate\.x64\.bin/ nocase ascii wide
        // Description: A POC of a new threadless process injection technique that works by utilizing the concept of DLL Notification Callbacks in local and remote processes.
        // Reference: https://github.com/ShorSec/DllNotificationInjection
        $string9 = "ShorSec/DllNotificationInjection" nocase ascii wide
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
