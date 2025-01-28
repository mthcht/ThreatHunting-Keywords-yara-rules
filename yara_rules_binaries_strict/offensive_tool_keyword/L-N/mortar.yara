rule mortar
{
    meta:
        description = "Detection patterns for the tool 'mortar' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mortar"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string1 = /\.\/encryptor\s\-f\s.{0,100}\.exe/
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string2 = /\/mimikatz\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string3 = /\/mortar\.git/ nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string4 = "/mortar/releases/download/v2/encryptor" nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string5 = "/mortar/releases/download/v2/encryptor" nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string6 = /\/mortar\-loader\.html/ nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string7 = /\\\\pipe\\\\moj_ML_ntsvcs/ nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string8 = /\\\\pipe\\\\MyNamePipe/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string9 = /\\mortar\\Lib\\shell_loader\.pas/ nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string10 = /\\mortar\-loader\.html/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string11 = /\\pipe\\moj_ML_ntsvcs\s/ nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string12 = "0xsp-SRD/mortar" nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string13 = "0xsp-SRD/mortar" nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string14 = "411305d5a0aac7535dc0b676e880c689f254f270f402ec98e395a322996f75da" nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string15 = "ac77cefd856217e33d5acc730ea62c1a63e77a7a2fdd587d6d9bbfcea3e4da1d" nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string16 = /cmd\.exe\s\/c\srundll32\.exe\sagressor\.dll.{0,100}stealth/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string17 = /deliver\.exe\s\-d\s\-c\s.{0,100}\s\-f.{0,100}\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string18 = /deliver\.exe\s\-d\s\-f\s.{0,100}\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string19 = /encryptor\s\-f\s.{0,100}\.exe\s\-o\s.{0,100}\.enc/ nocase ascii wide
        // Description: evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR)
        // Reference: https://github.com/0xsp-SRD/mortar
        $string20 = "f585b5225e1165fbeea3219ed3ce74988c60801831d5b7b1b2cc0bec1e4e4793" nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string21 = /mortar\-loader\.html/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string22 = /mortar\-main\.zip/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string23 = /rundll32\.exe\sagressor\.dll.{0,100}dec/ nocase ascii wide
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
