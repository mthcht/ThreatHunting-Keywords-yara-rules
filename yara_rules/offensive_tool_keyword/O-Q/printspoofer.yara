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
        $string1 = /.{0,1000}\.exe\s\-d\s3\s\-c\s.{0,1000}powershell\s\-ep\sbypass.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string2 = /.{0,1000}\/PrintSpoofer\.git.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string3 = /.{0,1000}B67143DE\-321D\-4034\-AC1D\-C6BB2D98563F.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string4 = /.{0,1000}itm4n\/PrintSpoofer.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string5 = /.{0,1000}nc\.exe\s\-l\s\-p\s1337.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string6 = /.{0,1000}PrintSpoofer\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string7 = /.{0,1000}PrintSpoofer\.exe.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string8 = /.{0,1000}PrintSpoofer\.sln.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string9 = /.{0,1000}PrintSpoofer32\.exe.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string10 = /.{0,1000}PrintSpoofer64\.exe.{0,1000}/ nocase ascii wide
        // Description: Abusing Impersonation Privileges on Windows 10 and Server 2019
        // Reference: https://github.com/itm4n/PrintSpoofer
        $string11 = /.{0,1000}PrintSpoofer\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
