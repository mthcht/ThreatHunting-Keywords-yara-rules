rule Invoke_RDPThief
{
    meta:
        description = "Detection patterns for the tool 'Invoke-RDPThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-RDPThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string1 = /\sRdpThief\.dll/ nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string2 = /\/Invoke\-RDPThief\.git/ nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string3 = /\/RdpThief\.dll/ nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string4 = /\[\+\]\sSuccessfully\sinjected\sinto\sprocess\s/ nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string5 = /\\RdpThief\.dll/ nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string6 = "e382edfe2f7c38cb3d6abd20c75e1ac24ddc19f921aba4b92dda3e1774e45240" nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string7 = "Invoke-RDPThief " nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string8 = /Invoke\-RDPThief\.ps1/ nocase ascii wide
        // Description: perform process injection on the target process and inject RDPthief into the process in order to capture cleartext credentials
        // Reference: https://github.com/The-Viper-One/Invoke-RDPThief
        $string9 = "The-Viper-One/Invoke-RDPThief" nocase ascii wide

    condition:
        any of them
}
