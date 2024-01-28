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
        $string8 = /ADFSRelay\s\-/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string9 = /ADFSRelay\-main/ nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string10 = /praetorian\.com\/blog\/relaying\-to\-adfs\-attacks\// nocase ascii wide
        // Description: NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS
        // Reference: https://github.com/praetorian-inc/ADFSRelay
        $string11 = /praetorian\-inc\/ADFSRelay/ nocase ascii wide

    condition:
        any of them
}
