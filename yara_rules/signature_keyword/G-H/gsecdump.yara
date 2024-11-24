rule gsecdump
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "signature_keyword"

    strings:
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string1 = "Adware/Gsecdump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string2 = /Hacktool\.Gsecdump/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string3 = "HackTool/Gsecdump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string4 = "HackTool:Win32/Gsecdump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string5 = "HTool-GSECDump" nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string6 = /PSWTool\.Win64\.Gsecdmp/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string7 = /Win32\/PSWTool\.Gsecdump/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string8 = "Win32:Gsecdump" nocase ascii wide

    condition:
        any of them
}
