rule KrakenMask
{
    meta:
        description = "Detection patterns for the tool 'KrakenMask' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrakenMask"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // Reference: https://github.com/RtlDallas/KrakenMask
        $string1 = /\/KrakenMask\.git/ nocase ascii wide
        // Description: A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // Reference: https://github.com/RtlDallas/KrakenMask
        $string2 = /C7E4B529\-6372\-449A\-9184\-74E74E432FE8/ nocase ascii wide
        // Description: A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // Reference: https://github.com/RtlDallas/KrakenMask
        $string3 = /Kraken\sMask\sby\s\@DallasFR/ nocase ascii wide
        // Description: A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // Reference: https://github.com/RtlDallas/KrakenMask
        $string4 = /KrakenMask\-main/ nocase ascii wide
        // Description: A sleep obfuscation tool is used to encrypt the content of the .text section with RC4 (using SystemFunction032). To achieve this encryption a ROP chain is employed with QueueUserAPC and NtContinue.
        // Reference: https://github.com/RtlDallas/KrakenMask
        $string5 = /RtlDallas\/KrakenMask/ nocase ascii wide

    condition:
        any of them
}
