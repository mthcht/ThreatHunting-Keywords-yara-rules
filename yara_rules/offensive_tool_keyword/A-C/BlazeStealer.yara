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
        $string1 = /.{0,1000}\/Pyobfadvance.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string2 = /.{0,1000}\/Pyobfexecute.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string3 = /.{0,1000}\/pyobfgood.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string4 = /.{0,1000}\/Pyobflite.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string5 = /.{0,1000}\/Pyobfpremium.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string6 = /.{0,1000}\/Pyobftoexe.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string7 = /.{0,1000}\/Pyobfuse.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string8 = /.{0,1000}\/Pyobfusfile.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string9 = /.{0,1000}\\Pyobfadvance.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string10 = /.{0,1000}\\Pyobfexecute.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string11 = /.{0,1000}\\pyobfgood.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string12 = /.{0,1000}\\Pyobflite.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string13 = /.{0,1000}\\Pyobfpremium.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string14 = /.{0,1000}\\Pyobftoexe.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string15 = /.{0,1000}\\Pyobfuse.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string16 = /.{0,1000}\\Pyobfusfile.{0,1000}/ nocase ascii wide
        // Description: Malicious python packages
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string17 = /MTE2NTc2MDM5MjY5NDM1NDA2MA\.GRSNK7\.OHxJIpJoZxopWpF_S3zy5v2g7k2vyiufQ183Lo/ nocase ascii wide

    condition:
        any of them
}
