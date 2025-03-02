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
        $string2 = "/RDPCredentialStealer/releases/download/" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string3 = "/RDPCredentialStealer/tarball/latest" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string4 = /\:\\Users\\Public\\Music\\.{0,1000}\.dll/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string5 = /\\bin\\HostX64\\x64\\c2\.dll/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string6 = /\\Public\\Music\\RDPCreds\.txt/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string7 = /\\RDPCreds\.txt/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string8 = /\\RDPCredsStealerDLL/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string9 = "118c2a7d06f9ac1aabdec653f236e04f3a697f59bef6f4e9c9ca1ea8acdc33db" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string10 = "118c2a7d06f9ac1aabdec653f236e04f3a697f59bef6f4e9c9ca1ea8acdc33db" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string11 = "2eeba6742b716b69144db95b0240d6d7a50d48f28f2dec83b003e74ff4958ad1" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string12 = "33d0f399-f79a-44a2-a487-21fce657be35" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string13 = "4358d271e8e3db49fc9ba98ab0709727f9043a129b5978ebaa23881f60b26b64" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string14 = "5eabd7d957e56a9cb9a918f7e9f72dc76a0481954c2f93ad5264095b5dbb6897" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string15 = "5eabd7d957e56a9cb9a918f7e9f72dc76a0481954c2f93ad5264095b5dbb6897" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string16 = "5eabd7d957e56a9cb9a918f7e9f72dc76a0481954c2f93ad5264095b5dbb6897" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string17 = "78fa6d6f41b506791944c470b4cceb3af184a9c6fcaa804d706763cb9c29b52b" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string18 = "7ef6a655e0c09263822565e5022ff3bd33494f1bedc2062862f769ebd2c93897" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string19 = /APIHookInjectorBin\.exe/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string20 = /APIHookInjectorBin\.log/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string21 = /APIHookInjectorBin\.pdb/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string22 = /APIHookInjectorBin\.sln/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string23 = "e8930c16d171577f55aa0cbdd8fe5fe656bba46751cd44e2e2fda325b6f6e9b9" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string24 = "ea17314d15bea466526ba9ca154009f04f46da461899ac4533d00479317703b8" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string25 = "ec2aaff0-b349-4855-9093-96acf6ee3299" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string26 = /RDPCredentialStealer\.zip/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string27 = "RDPCredentialStealer-main" nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string28 = /RDPCredsStealerDLL\./ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string29 = /RDPCredsStealerDLL\.dll/ nocase ascii wide
        // Description: RDPCredentialStealer it's a malware that steal credentials provided by users in RDP using API Hooking with Detours in C++
        // Reference: https://github.com/S12cybersecurity/RDPCredentialStealer
        $string30 = "S12cybersecurity/RDPCredentialStealer" nocase ascii wide

    condition:
        any of them
}
