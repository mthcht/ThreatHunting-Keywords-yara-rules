rule BetterSafetyKatz
{
    meta:
        description = "Detection patterns for the tool 'BetterSafetyKatz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BetterSafetyKatz"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = "aHR0cDovL3BpbmdjYXN0bGUuY29t" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = /BetterSafetyKatz\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = "bG9nb25QYXNzd29yZHM=" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = "bWltaWthdHo=" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = "dmluY2VudC5sZXRvdXhAZ21haWwuY29t" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = "eDY0L21pbWlrYXR6LmV4ZQ==" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string7 = "L3NhbSBvciAvc2lkIHRvIHRhcmdldCB0aGUgYWNjb3VudCBpcyBuZWVkZWQ=" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string8 = "Process is not 64-bit, this version of katz won't work yo'!" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string9 = "QmVuamFtaW4gREVMUFk=" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string10 = "QSBMYSBWaWUsIEEgTCdBbW91cg==" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string11 = "RHVtcENyZWRz" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string12 = "S2l3aUFuZENNRA==" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string13 = "TGlzdHMgYWxsIGF2YWlsYWJsZSBwcm92aWRlcnMgY3JlZGVudGlhbHM=" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string14 = "U3dpdGNoIChvciByZWluaXQpIHRvIExTQVNTIHByb2Nlc3MgIGNvbnRleHQ=" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string15 = "W2V4cGVyaW1lbnRhbF0gcGF0Y2ggVGVybWluYWwgU2VydmVyIHNlcnZpY2UgdG8gYWxsb3cgbXVsdGlwbGVzIHVzZXJz" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string16 = "Z2VudGlsa2l3aQ==" nocase ascii wide

    condition:
        any of them
}
