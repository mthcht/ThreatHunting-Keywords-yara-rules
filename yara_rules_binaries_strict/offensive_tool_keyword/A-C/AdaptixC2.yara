rule AdaptixC2
{
    meta:
        description = "Detection patterns for the tool 'AdaptixC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AdaptixC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string1 = /\/AdapticClient\.exe/ nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string2 = /\/AdaptixC2\.git/ nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string3 = /\\AdapticClient\.exe/ nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string4 = "9117d2d155a124e050aaf1c64011f5a65198f9dd91289ffcf809f8364740f1d5" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string5 = "99a5f42e-60a8-4f1e-9dff-35443b972707" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string6 = "AdaptixClient/AdaptixClient" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string7 = "Adaptix-Framework/AdaptixC2" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string8 = "AdaptixServer -p" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string9 = "AdaptixServer/adaptixserver" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string10 = "d886eb849d99a52449eb869bdf954644c2d5259db29be9cc757084bf166c42e0" nocase ascii wide
        // Description: C2- Adaptix is an extensible post-exploitation and adversarial emulation framework made for penetration testers
        // Reference: https://github.com/Adaptix-Framework/AdaptixC2
        $string11 = /https\:\/\/adaptix\-framework\.gitbook\.io\/adaptix\-framework\/adaptix\-c2\/getting\-starting\// nocase ascii wide
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
