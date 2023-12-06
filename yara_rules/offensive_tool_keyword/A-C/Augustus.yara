rule Augustus
{
    meta:
        description = "Detection patterns for the tool 'Augustus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Augustus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Augustus is a Golang loader that execute shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.
        // Reference: https://github.com/TunnelGRE/Augustus
        $string1 = /\/3DESEncryptor\.go/ nocase ascii wide
        // Description: Augustus is a Golang loader that execute shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.
        // Reference: https://github.com/TunnelGRE/Augustus
        $string2 = /\/Augustus\.git/ nocase ascii wide
        // Description: Augustus is a Golang loader that execute shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.
        // Reference: https://github.com/TunnelGRE/Augustus
        $string3 = /Augustus\-main\.zip/ nocase ascii wide
        // Description: Augustus is a Golang loader that execute shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.
        // Reference: https://github.com/TunnelGRE/Augustus
        $string4 = /TunnelGRE\/Augustus/ nocase ascii wide

    condition:
        any of them
}
