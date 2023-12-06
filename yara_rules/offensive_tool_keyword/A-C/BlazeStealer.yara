rule BlazeStealer
{
    meta:
        description = "Detection patterns for the tool 'BlazeStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlazeStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string1 = /\/Pyobfadvance/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string2 = /\/Pyobfexecute/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string3 = /\/pyobfgood/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string4 = /\/Pyobflite/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string5 = /\/Pyobfpremium/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string6 = /\/Pyobftoexe/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string7 = /\/Pyobfuse/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string8 = /\/Pyobfusfile/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string9 = /\\Pyobfadvance/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string10 = /\\Pyobfexecute/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string11 = /\\pyobfgood/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string12 = /\\Pyobflite/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string13 = /\\Pyobfpremium/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string14 = /\\Pyobftoexe/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string15 = /\\Pyobfuse/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string16 = /\\Pyobfusfile/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string17 = /MTE2NTc2MDM5MjY5NDM1NDA2MA\.GRSNK7\.OHxJIpJoZxopWpF_S3zy5v2g7k2vyiufQ183Lo/ nocase ascii wide

    condition:
        any of them
}
