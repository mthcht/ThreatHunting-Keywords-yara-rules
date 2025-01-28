rule SharpMove
{
    meta:
        description = "Detection patterns for the tool 'SharpMove' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpMove"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\.exe\saction\=dcom\scomputername\=.{0,1000}\scommand\=.{0,1000}\sthrow\=wmi\s/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string2 = /\/SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string3 = /\/SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string4 = /\/SharpMove\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string6 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string7 = /\\SharpMove\.sln/ nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string8 = "0xthirteen/SharpMove" nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string9 = "4592e0848e4929ac2b6ba4593f8cbfe09f52ce6ca4206ce52087a31073903645" nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string10 = "6093461c4db41a15fefc85a28e35a9e359d0e9452bbfd36ce1fbe7aa31e1f4f0" nocase ascii wide
        // Description: .NET Project for performing Authenticated Remote Execution
        // Reference: https://github.com/0xthirteen/SharpMove
        $string11 = "8BF82BBE-909C-4777-A2FC-EA7C070FF43E" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string12 = "'Product'>SharpMove" nocase ascii wide

    condition:
        any of them
}
