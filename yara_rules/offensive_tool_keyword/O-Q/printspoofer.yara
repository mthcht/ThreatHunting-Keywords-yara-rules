rule PrintSpoofer
{
    meta:
        description = "Detection patterns for the tool 'PrintSpoofer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrintSpoofer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string1 = /\/PrintSpoofer\.git/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string2 = /itm4n\/PrintSpoofer/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string3 = /PrintSpoofer\.cpp/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string4 = /PrintSpoofer\.exe/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string5 = /PrintSpoofer\.sln/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string6 = /PrintSpoofer32\.exe/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string7 = /PrintSpoofer64\.exe/ nocase ascii wide

    condition:
        any of them
}
