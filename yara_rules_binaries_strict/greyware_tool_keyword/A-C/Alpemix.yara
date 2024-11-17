rule Alpemix
{
    meta:
        description = "Detection patterns for the tool 'Alpemix' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alpemix"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string1 = /\/Alpemix\.zip/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string2 = /\/Apemix\.exe/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string3 = /\\Alpemix\.ini/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string4 = /\\Alpemix\.zip/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string5 = /\\Apemix\.exe/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string6 = /\\CurrentControlSet\\Services\\AlpemixSrvcx/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string7 = /\<Alpemix\>/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string8 = /\<AlpemixWEB\>/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string9 = /\<Teknopars\sBilisim\>/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string10 = /3660fe9f10b94d38fecaea009e6625850a46b1d47bb7788fc47f286c1008e2ec/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string11 = /6badff5495258b349559b9d2154ffcc7a435828dd57c4caf1c79f5d0ff9eb675/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string12 = /c5e68c5635bed872ce6ac0c2be5395cc15c2dbaa5f0052b86575cdd0b762902e/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string13 = /serverinfo\.alpemix\.com/ nocase ascii wide
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
