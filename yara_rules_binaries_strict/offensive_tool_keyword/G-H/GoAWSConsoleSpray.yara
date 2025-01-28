rule GoAWSConsoleSpray
{
    meta:
        description = "Detection patterns for the tool 'GoAWSConsoleSpray' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GoAWSConsoleSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string1 = /\.\/GoAWSConsoleSpray/
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string2 = /\/GoAWSConsoleSpray\.git/ nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string3 = /\\GoAWSConsoleSpray\-master/ nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string4 = "53f349d9fefb61b435f3b257f63ec8720b92cc4446cc08455e53ba9c5ca8071c" nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string5 = "AWS Account Bruteforce Ratelimit! Sleeping for " nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string6 = "b096ce8b9397269012bccaef5a419211cb74d1157d4340453a3a39b68da7cf10" nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string7 = "bin/GoAWSConsoleSpray" nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string8 = "GoAWSConsoleSpray -" nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string9 = /GoAWSConsoleSpray\.exe/ nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string10 = "GoAWSConsoleSpray@latest" nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string11 = /GoAWSConsoleSpray\-master\.zip/ nocase ascii wide
        // Description: brute-force AWS IAM Console credentials to discover valid logins for user accounts
        // Reference: https://github.com/WhiteOakSecurity/GoAWSConsoleSpray
        $string12 = "WhiteOakSecurity/GoAWSConsoleSpray" nocase ascii wide
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
