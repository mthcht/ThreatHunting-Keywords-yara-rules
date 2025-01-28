rule MultiPotato
{
    meta:
        description = "Detection patterns for the tool 'MultiPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MultiPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string1 = /\s\-t\sBindShell\s\-p\s.{0,100}pwned\\pipe\\spoolss/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string2 = /\s\-t\sCreateProcessAsUserW\s\-p\s.{0,100}pwned\\pipe\\spoolss.{0,100}\s\-e\s.{0,100}\.exe/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string3 = /\/MultiPotato\.git/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string4 = /\\\\\.\\pipe\\pwned\/pipe\/srvsvc/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string5 = "61CE6716-E619-483C-B535-8694F7617548" nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string6 = "localhost/pipe/pwned" nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string7 = /MS\-RPRN\.exe\s\\\\.{0,100}\s\\\\.{0,100}\/pipe\/pwned/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string8 = /MultiPotato\.cpp/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string9 = /MultiPotato\.exe/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string10 = "MultiPotato-main" nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string11 = /PetitPotamModified\.exe/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string12 = "S3cretP4ssw0rd!" nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string13 = "S3cur3Th1sSh1t/MultiPotato" nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string14 = /TokenKidnapping\.cpp/ nocase ascii wide
        // Description: get SYSTEM via SeImpersonate privileges
        // Reference: https://github.com/S3cur3Th1sSh1t/MultiPotato
        $string15 = /TokenKidnapping\.exe/ nocase ascii wide
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
