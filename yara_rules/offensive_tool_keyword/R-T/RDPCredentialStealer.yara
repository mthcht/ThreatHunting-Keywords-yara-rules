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
        $string1 = /.{0,1000}\/RDPCredentialStealer\.git.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string2 = /.{0,1000}:\\Users\\Public\\Music\\.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string3 = /.{0,1000}\\Public\\Music\\RDPCreds\.txt.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string4 = /.{0,1000}\\RDPCredsStealerDLL.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string5 = /.{0,1000}APIHookInjectorBin\.exe.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string6 = /.{0,1000}APIHookInjectorBin\.log.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string7 = /.{0,1000}APIHookInjectorBin\.pdb.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string8 = /.{0,1000}APIHookInjectorBin\.sln.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string9 = /.{0,1000}RDPCredentialStealer\.zip.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string10 = /.{0,1000}RDPCredentialStealer\-main.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string11 = /.{0,1000}RDPCredsStealerDLL\..{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string12 = /.{0,1000}RDPCredsStealerDLL\.dll.{0,1000}/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string13 = /.{0,1000}S12cybersecurity\/RDPCredentialStealer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
