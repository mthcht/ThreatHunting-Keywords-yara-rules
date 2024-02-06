rule RDPCredentialStealer
{
    meta:
        description = "Detection patterns for the tool 'RDPCredentialStealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RDPCredentialStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string1 = /\/RDPCredentialStealer\.git/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string2 = /\:\\Users\\Public\\Music\\.{0,1000}\.dll/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string3 = /\\Public\\Music\\RDPCreds\.txt/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string4 = /\\RDPCredsStealerDLL/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string5 = /APIHookInjectorBin\.exe/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string6 = /APIHookInjectorBin\.log/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string7 = /APIHookInjectorBin\.pdb/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string8 = /APIHookInjectorBin\.sln/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string9 = /RDPCredentialStealer\.zip/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string10 = /RDPCredentialStealer\-main/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string11 = /RDPCredsStealerDLL\./ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string12 = /RDPCredsStealerDLL\.dll/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string13 = /S12cybersecurity\/RDPCredentialStealer/ nocase ascii wide

    condition:
        any of them
}
