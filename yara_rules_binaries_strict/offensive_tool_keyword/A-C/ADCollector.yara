rule ADCollector
{
    meta:
        description = "Detection patterns for the tool 'ADCollector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADCollector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string1 = "  --LocalGMEnum --Host " nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string2 = /\sADCollector\.exe/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string3 = " --SessionEnum --Host " nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string4 = " --UserEnum --Host " nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string5 = /\.exe\s\-\-ACLScan\s.{0,100}\s\-\-OU\s/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string6 = /\.exe\s\-\-LDAPs\s\-\-DisableSigning/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string7 = /\/ADCollector\.exe/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string8 = /\/ADCollector\.git/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string9 = /\\ADCollector\.exe/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string10 = /\\ADCollector3\.sln/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string11 = /\\ADCollector3\\/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string12 = "16e9f3c3f2a4264e3be9d2ddfe8d4ad409f4db17c077efd372389fbfe89f727b" nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string13 = "558a73bf1f4a3ecc59133a10d1a7892712f2bd30326f86a12d5c7060274d734d" nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string14 = /ADCollector3\.csproj/ nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string15 = "D1AE1ACF-8AA2-4935-ACDF-EC22BAE2DF76" nocase ascii wide
        // Description: ADCollector is a lightweight tool that enumerates the Active Directory environment
        // Reference: https://github.com/dev-2null/ADCollector
        $string16 = "dev-2null/ADCollector" nocase ascii wide
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
