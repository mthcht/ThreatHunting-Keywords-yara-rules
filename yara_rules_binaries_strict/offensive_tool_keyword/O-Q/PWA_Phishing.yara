rule PWA_Phishing
{
    meta:
        description = "Detection patterns for the tool 'PWA-Phishing' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWA-Phishing"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string1 = /\/mrd0x\.html/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string2 = /\/PWA\-Phishing\.git/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string3 = /\\PWA\-Phishing/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string4 = "18c54c69f41d0b7e5928c34e1e9350ed99ecd0278ea37df11a429018ca3d05ed" nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string5 = "3b1e2b01bfa6ad0deefa3bf8e7a81e9fc295e56b8f087ef402d9a06e42ec3b95" nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string6 = "95b9a6d12b978a6c1bbd6a33369e39008e7d64544d50c98c9c3f2b93a9466e79" nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string7 = "bfa9dc4c4b911b6777cb98d17a82b28531c26600698699cbe658749684818f28" nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string8 = /fopen\(\'credentials\.txt\'/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string9 = /https\:\/\/mrd0x\.com\/progressive\-web\-apps\-pwa\-phishing/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string10 = "mrd0x/PWA-Phishing" nocase ascii wide
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
