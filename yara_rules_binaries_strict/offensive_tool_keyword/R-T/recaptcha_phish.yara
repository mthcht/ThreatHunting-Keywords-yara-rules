rule recaptcha_phish
{
    meta:
        description = "Detection patterns for the tool 'recaptcha-phish' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "recaptcha-phish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string1 = /\/recaptcha\-phish\.git/ nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string2 = "/recaptcha-phish-main" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string3 = /\\recaptcha\-phish\-main/ nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string4 = "4f2678fa0f90074ae304f8fdb9174d0c577f1a0587af44a4e8e756a547e5c2e4" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string5 = "9593cc106f75cc415faadbeb5b16fa79cfe8c047ad007d50dbf8cb1d242126de" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string6 = /const\scommandToRun\s\=\s\\"mshta\s\\"\s\+\shtaPath/ nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string7 = "I am not a robot - reCAPTCHA Verification ID: 2165" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string8 = "I am not a robot - reCAPTCHA Verification ID: 3029" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string9 = "I am not a robot - reCAPTCHA Verification ID: 4202" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string10 = "I am not a robot - reCAPTCHA Verification ID: 7537" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string11 = "I am not a robot - reCAPTCHA Verification ID: 7624" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string12 = "I am not a robot - reCAPTCHA Verification ID: 93752" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string13 = "JohnHammond/recaptcha-phish" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string14 = /mshta.{0,100}I\sam\snot\sa\srobot\s\-\s.{0,100}Verification\sID\:\s/ nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string15 = /mshta\.exe.{0,100}I\sam\snot\sa\srobot\s\-\sreCAPTCHA\sVerification\sID\:\s/ nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string16 = /objShell\.Run\s\\"calc\.exe\\"/ nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string17 = "reCAPTCHA Verification ID: <span id=\"verification-id\">146820</span>" nocase ascii wide
        // Description: Phishing with a fake reCAPTCHA
        // Reference: https://github.com/JohnHammond/recaptcha-phish
        $string18 = /recaptcha\-phish\-main\.zip/ nocase ascii wide
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
