rule MANSPIDER
{
    meta:
        description = "Detection patterns for the tool 'MANSPIDER' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MANSPIDER"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string1 = " --dirnames bank financ payable payment reconcil remit voucher vendor eft swift " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string2 = " -e bat com vbs ps1 psd1 psm1 pem key rsa pub reg txt cfg conf config " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string3 = " -e pfx p12 pkcs12 pem key crt cer csr jks keystore key keys der " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string4 = " -e ppk rsa pem ssh rsa" nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string5 = " -f passw -e xlsx csv " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string6 = " -f passw user admin account network login logon cred " nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string7 = /\/\.manspider\/logs/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string8 = /\/\.manspider\/loot/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string9 = /\/MANSPIDER\.git/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string10 = /\/manspider_.{0,100}\.log/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string11 = /\/tmp\/\.manspider/
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string12 = /\\manspider_.{0,100}\.log/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string13 = "blacklanternsecurity/MANSPIDER" nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string14 = /man_spider\.manspider\:main/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string15 = /manspider\s.{0,100}\s\-d\s.{0,100}\s\-u\s.{0,100}\s\-p\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string16 = /manspider\s.{0,100}\/24\s\-f\s/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string17 = /manspider.{0,100}\-\-loot\-dir/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string18 = /manspider.{0,100}\-\-sharenames/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string19 = /manspider\.py/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string20 = /manspider\.spiderling/ nocase ascii wide
        // Description: Spider entire networks for juicy files sitting on SMB shares. Search filenames or file content - regex supported!
        // Reference: https://github.com/blacklanternsecurity/MANSPIDER
        $string21 = "MANSPIDER-master" nocase ascii wide
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
