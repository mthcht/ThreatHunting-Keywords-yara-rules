rule ADSyncDecrypt
{
    meta:
        description = "Detection patterns for the tool 'ADSyncDecrypt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ADSyncDecrypt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\\ADSyncDecrypt\\/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = ">ADSyncDecrypt<" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /ADSyncDecrypt\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9nZW50aWxraXdpL21pbWlrYXR6L3JlbGVhc2VzL2xhdGVzdA==" nocase ascii wide

    condition:
        any of them
}
