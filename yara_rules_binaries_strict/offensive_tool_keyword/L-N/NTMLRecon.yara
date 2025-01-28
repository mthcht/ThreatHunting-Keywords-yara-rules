rule NTMLRecon
{
    meta:
        description = "Detection patterns for the tool 'NTMLRecon' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTMLRecon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string1 = " ntlmrecon" nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string2 = "/NTLMRecon" nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string3 = /\/NTLMRecon\.git/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string4 = /\/ntlmrecon\/.{0,100}\.py/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string5 = /\/ntlmutil\.py/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string6 = /\/ntlmutil\.py/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string7 = /\\ntlmutil\.py/ nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string8 = "ntlmrecon " nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string9 = /ntlmrecon\.csv/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string10 = "ntlmrecon:main" nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string11 = /ntlmrecon\-fromfile\.csv/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string12 = "NTLMRecon-master" nocase ascii wide
        // Description: A fast and flexible NTLM reconnaissance tool without external dependencies. Useful to find out information about NTLM endpoints when working with a large set of potential IP addresses and domains
        // Reference: https://github.com/pwnfoo/NTLMRecon
        $string13 = /ntlmrecon\-ranges\.csv/ nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string14 = "puzzlepeaches/NTLMRecon" nocase ascii wide
        // Description: Enumerate information from NTLM authentication enabled web endpoints
        // Reference: https://github.com/puzzlepeaches/NTLMRecon
        $string15 = "TlRMTVNTUAABAAAAMpCI4gAAAAAoAAAAAAAAACgAAAAGAbEdAAAADw==" nocase ascii wide
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
