rule RottenPotatoNG
{
    meta:
        description = "Detection patterns for the tool 'RottenPotatoNG' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RottenPotatoNG"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string1 = " CMSFRottenPotato::" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string2 = /\/RottenPotatoNG\.git/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string3 = /\\MSFRottenPotato\.cpp/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string4 = /\\MSFRottenPotato\.log/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string5 = /\\MSFRottenPotato\.sln/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string6 = /\\MSFRottenPotatoTestHarness\./ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string7 = /\\RottenPotatoNG\-main/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string8 = /\\RottenPotatoNG\-master/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string9 = "0fb342f94f359c9f54205a979854b7a3a3910bb7e118f0fc44cead28ebd81f0d" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string10 = "1d6d4c0b001fc20d404d6e2ec3625d9fc245c31484023e2ac7a3b123eec8cce1" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string11 = "2e67c9adb1962e9b5c9a025b2901fc01e2a214b53f5552656a07f2057307f6e5" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string12 = "3a0b118ddd6b02426aba9ead93a576f7b99997cf6f07907147dd0d3294ff8887" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string13 = "4164003E-BA47-4A95-8586-D5AAC399C050" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string14 = "44ae8a2088ca416ed3c802f50eb55adbbb2d01fd528e76be8dd449004ce470ad" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string15 = "4a9d528dc102560378cff97262caeae12e24e64b94e381e6e5709e3b2bb89291" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string16 = "4d1fd422503b03f89fba5fa6d51e5bccb3e6cd3254461de316ca25296da38d4b" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string17 = "5952e312083c8121c4856b566421aa23afe427e7f1eb0b4e6ae34515b906705a" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string18 = "62971b70cd61bff1243ad58121912ea8aa7ee1cfb553b2310cbbd4c32529e151" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string19 = "73141d2560cc8922220ff44a83d36aa79e759ae349dea6300cf6c4adde81982d" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string20 = "7E1BCC8E-F61C-4728-BB8A-28FB42928256" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string21 = "889dc7cce75cae74fe761345fc1f0e02e8b97f705c92a5a136666250301a1215" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string22 = "889dc7cce75cae74fe761345fc1f0e02e8b97f705c92a5a136666250301a1215" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string23 = "8aed04233ee4b33500c6af6da612bed71770628910a761c325987d24737c5c28" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string24 = "9302e09f9f1856391bc218c2b7cdd898e8934f18efc31dd9b27f52b0e2d1812c" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string25 = "9d584d6906a84285108c0500cab449e016a42bfd2b365f19ae851ff5312e2a33" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string26 = "be038bcb58b9e744c9821823ac59c3d9f4cc9456f445c41a840b7a6acbc21fc3" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string27 = "breenmachine/RottenPotatoNG" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string28 = "e30560b23a52a32b2ad8250466c1b0a975348ab4f6240e629288bc4ad74430fb" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string29 = "e30560b23a52a32b2ad8250466c1b0a975348ab4f6240e629288bc4ad74430fb" nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string30 = /MSFRottenPotato\.dll/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string31 = /MSFRottenPotato\.exe/ nocase ascii wide
        // Description: perform the RottenPotato attack and get a handle to a privileged token
        // Reference: https://github.com/breenmachine/RottenPotatoNG
        $string32 = /MSFRottenPotatoTestHarness\.exe/ nocase ascii wide
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
