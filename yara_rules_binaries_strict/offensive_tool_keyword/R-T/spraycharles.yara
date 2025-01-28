rule spraycharles
{
    meta:
        description = "Detection patterns for the tool 'spraycharles' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "spraycharles"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string1 = " install spraycharles" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string2 = /\sspray\s\-u\s.{0,100}\s\-H\s.{0,100}\s\-p\s.{0,100}\s\-m\sowa/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string3 = /\sspray\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-m\sOffice365/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string4 = /\sspray\s\-u\s.{0,100}\s\-p\s.{0,100}\s\-m\sSmb\s\-H\s/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string5 = /\sspraycharles\.py/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string6 = /\/\.spraycharles\/logs/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string7 = /\/\.spraycharles\/out/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string8 = /\/\.spraycharles\:\/root\/\.spraycharles/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string9 = /\/root\/\.local\/bin\/spraycharles/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string10 = /\/spraycharles\.git/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string11 = /\/spraycharles\.py/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string12 = /\/tmp\/passwords\.txt/
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string13 = /\\spraycharles\.py/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string14 = "a89da438ecbe2e8c5f65e2bcbf5d82a84d26ba56dff46eb180c9de213f5a1871" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string15 = /docker\sbuild\s\.\s\-t\sspraycharles/ nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string16 = "from spraycharles import " nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string17 = "spraycharles analyze " nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string18 = "spraycharles gen extras" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string19 = "spraycharles spray" nocase ascii wide
        // Description: Low and slow password spraying tool
        // Reference: https://github.com/Tw1sm/spraycharles
        $string20 = "Tw1sm/spraycharles" nocase ascii wide
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
