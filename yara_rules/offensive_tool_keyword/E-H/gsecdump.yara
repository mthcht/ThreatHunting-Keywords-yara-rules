rule gsecdump
{
    meta:
        description = "Detection patterns for the tool 'gsecdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsecdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string1 = /\s\-\-dump_lsa/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string2 = /\s\-\-dump_usedhashes/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string3 = /\s\-\-dump_wireless/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string4 = /\/gsecdump\-.{0,1000}\.exe/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string5 = /\/gsecdump\.exe/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string6 = /\\gsecdump\-.{0,1000}\.exe/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string7 = /\\gsecdump\.exe/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string8 = /\\pipe\\gsecdump_/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string9 = /\>\\gsecdump_/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string10 = /94cae63dcbabb71c5dd43f55fd09caeffdcd7628a02a112fb3cba36698ef72bc/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string11 = /gsecdump\-v2b5\.exe/ nocase ascii wide
        // Description: credential dumper used to obtain password hashes and LSA secrets from Windows operating systems	
        // Reference: https://web.archive.org/web/20150606043951if_/http://www.truesec.se/Upload/Sakerhet/Tools/gsecdump-v2b5.exe
        $string12 = /pipe\\\\gsecdump_/ nocase ascii wide

    condition:
        any of them
}
