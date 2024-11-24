rule ADFSRelay
{
    meta:
        description = "Detection patterns for the tool 'ADFSRelay' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADFSRelay"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string1 = /\s\|\sNTLMParse/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string2 = /\/ADFSRelay\.git/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string3 = /\/ADFSRelay\.go/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string4 = /\/NTLMParse\.go/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string5 = /\/releases\/download\/v1\.0\/ADFSRelay/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string6 = /\/releases\/download\/v1\.0\/NTLMParse/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string7 = /\\ADFSRelay\\/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string8 = "ADFSRelay -" nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string9 = "ADFSRelay-main" nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string10 = /praetorian\.com\/blog\/relaying\-to\-adfs\-attacks\// nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string11 = "praetorian-inc/ADFSRelay" nocase ascii wide
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
