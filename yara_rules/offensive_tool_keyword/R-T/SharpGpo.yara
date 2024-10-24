rule SharpGpo
{
    meta:
        description = "Detection patterns for the tool 'SharpGpo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpGpo"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\s\-\-Action\sNewSecurityFiltering\s\-\-GPOName\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = /\s\-\-Action\sRemoveSecurityFiltering\s\-\-GPOName\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\.exe\s\-\-Action\sGetGPLink\s\-\-/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /\.exe\s\-\-Action\sGetGPO\s\-\-/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\.exe\s\-\-Action\sMoveObject\s\-\-/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string6 = /\.exe\s\-\-Action\sNewGPLink\s\-\-DN\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string7 = /\.exe\s\-\-Action\sRemoveGPLink\s\-\-DN\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string8 = /\.exe\s\-\-Action\sRemoveGPO\s\-\-/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string9 = /\.exe\s\-\-Action\sRemoveOU\s\-\-/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string10 = /\/SharpGpo\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string11 = /\\SharpGpo\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string12 = /\\SharpGPOAbuse\-master/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string13 = /\>SharpGPO\</ nocase ascii wide

    condition:
        any of them
}
