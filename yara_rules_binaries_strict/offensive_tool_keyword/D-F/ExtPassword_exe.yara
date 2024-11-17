rule ExtPassword_exe
{
    meta:
        description = "Detection patterns for the tool 'ExtPassword.exe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ExtPassword.exe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string1 = /\/extpassword\.zip/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string2 = /\/utils\/external_drive_password_recovery\.html/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string3 = /\\ExtPassword\.chm/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string4 = /\\ExtPassword\.html/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string5 = /\\extpassword\.zip/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string6 = /\\ExtPassword_lng\.ini/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string7 = /03a544b51ade8258a377800fda3237ce6f36ebae34e6787380c0a2f341b591e9/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string8 = /bd61c5daaad30b420817fb1fd2f0447c3b66a1900ba69fd4cd724d1e6897ab41/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string9 = /External\sDrive\sPassword\sRecovery/ nocase ascii wide
        // Description: Nirsoft tool for Windows that allows you to recover passwords stored on external drive plugged to your computer
        // Reference: https://www.nirsoft.net/utils/external_drive_password_recovery.html
        $string10 = /ExtPassword\.exe/ nocase ascii wide
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
