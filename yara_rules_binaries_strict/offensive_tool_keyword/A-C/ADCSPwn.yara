rule ADCSPwn
{
    meta:
        description = "Detection patterns for the tool 'ADCSPwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCSPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string1 = /\.exe\s\-\-adcs\s.{0,100}\s\-\-remote\s/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string2 = /\/ADCSPwn\.git/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string3 = /\\ADCSPwn/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string4 = ">ADCSPwn<" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string5 = "0bb4b892f67fdf903ed5e5df2c85c5ccb71669c298736cf24284412de435509a" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string6 = "980EF05F-87D1-4A0A-932A-582FB1BC3AC3" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string7 = /ADCSPwn\.csproj/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string8 = /ADCSPwn\.exe/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string9 = /ADCSPwn\.sln/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string10 = /ADCSPwn\.zip/ nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string11 = "ADCSPwn-master" nocase ascii wide
        // Description: A tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
        // Reference: https://github.com/bats3c/ADCSPwn
        $string12 = "bats3c/ADCSPwn" nocase ascii wide
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
