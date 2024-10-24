rule PrintSpoofer
{
    meta:
        description = "Detection patterns for the tool 'PrintSpoofer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\/PrintSpoofer\.exe/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string2 = /\/PrintSpoofer\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\\PrintSpoofer\.exe/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string4 = /itm4n\/PrintSpoofer/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /PrintSpoofer\sv\%ws\s\(by\s\@itm4n\)/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string6 = /PrintSpoofer\.cpp/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string7 = /PrintSpoofer\.exe/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string8 = /PrintSpoofer\.sln/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string9 = /PrintSpoofer32\.exe/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string10 = /PrintSpoofer64\.exe/ nocase ascii wide

    condition:
        any of them
}
