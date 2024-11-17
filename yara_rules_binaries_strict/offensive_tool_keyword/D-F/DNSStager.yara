rule DNSStager
{
    meta:
        description = "Detection patterns for the tool 'DNSStager' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNSStager"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string1 = /\sdnsstager\.py/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string2 = /\sIPV6\saddresses\sxored\s/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string3 = /\s\-\-payload\s.{0,100}\s\-\-shellcode_path\s.{0,100}\s\-\-xorkey\s/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string4 = /\s\-\-payload\sx64\/c\/ipv6\s/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string5 = /\/DNSStager\.git/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string6 = /\/dnsstager\.py/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string7 = /\\dnsstager\.py/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string8 = /build_c_xor_ipv6\(/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string9 = /build_c_xor_ipv6_dll\(/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string10 = /build_golang_xor_ipv6\(/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string11 = /DNSStager\spayloads\sAvailable/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string12 = /DNSStager\swill\s/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string13 = /encode_xor_shellcode\(/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string14 = /f15f6182ca98bb702c2578efc0aef6e35d8237b89a00a588364bb7e068b132fa/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string15 = /mhaskar\/DNSStager/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string16 = /run\sDNSStager\sas\sroot/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string17 = /sudo\s\.\/dnsstager/ nocase ascii wide
        // Description: DNSStager is an open-source project based on Python used to hide and transfer your payload using DNS.
        // Reference: https://github.com/mhaskar/DNSStager
        $string18 = /We\srecommend\sto\sXOR\syour\sshellcode\sbefore\syou\stransfer\sit/ nocase ascii wide
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
