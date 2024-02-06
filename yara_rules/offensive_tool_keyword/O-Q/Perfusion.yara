rule Perfusion
{
    meta:
        description = "Detection patterns for the tool 'Perfusion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Perfusion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string1 = /\/Perfusion\.exe/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string2 = /\/Perfusion\.git/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string3 = /\/PerfusionDll\.dll/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string4 = /\[\!\]\sFailed\sto\sdelete\sPerformance\sregistry\skey\./ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string5 = /\[\-\]\sFailed\sto\sdelete\sPerformance\sDLL/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string6 = /\[\+\]\sExploit\scompleted\.\sGot\sa\sSYSTEM\stoken\!\s\:\)/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string7 = /\\Perfusion\.cpp/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string8 = /\\Perfusion\.exe/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string9 = /\\Perfusion\.sln/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string10 = /\\PerfusionDll\.cpp/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string11 = /\\PerfusionDll\.dll/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string12 = /\\PerfusionDll\.log/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string13 = /1B1F64B3\-B8A4\-4BBB\-BB66\-F020E2D4F288/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string14 = /A7397316\-0AEF\-4379\-B285\-C276DE02BDE1/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string15 = /C\:\\Users\\.{0,1000}\\AppData\\Local\\Temp\\performance_636_3000_1\.dll/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string16 = /https\:\/\/itm4n\.github\.io\/windows\-registry\-rpceptmapper\-eop\// nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string17 = /itm4n\/Perfusion/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string18 = /Perfusion\.exe\s\-c/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string19 = /Perfusion\\RegistryPatch\.ps1/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string20 = /Perfusion\-master\.zip/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string21 = /WritePayloadDll\(LPWSTR\spwszDllPath\)/ nocase ascii wide

    condition:
        any of them
}
