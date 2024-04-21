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
        $string3 = /\s\-\-payload\s.{0,1000}\s\-\-shellcode_path\s.{0,1000}\s\-\-xorkey\s/ nocase ascii wide
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

    condition:
        any of them
}
