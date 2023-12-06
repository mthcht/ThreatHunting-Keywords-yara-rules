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
        $string1 = /\.exe\s\-d\s3\s\-c\s.{0,1000}powershell\s\-ep\sbypass/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string2 = /\/PrintSpoofer\.git/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string3 = /B67143DE\-321D\-4034\-AC1D\-C6BB2D98563F/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string4 = /itm4n\/PrintSpoofer/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string5 = /nc\.exe\s\-l\s\-p\s1337/ nocase ascii wide
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
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string11 = /PrintSpoofer\-master/ nocase ascii wide

    condition:
        any of them
}
