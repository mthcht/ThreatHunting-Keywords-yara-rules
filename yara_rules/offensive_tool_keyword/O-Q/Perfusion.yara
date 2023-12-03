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
        $string1 = /.{0,1000}\/Perfusion\.exe.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string2 = /.{0,1000}\/Perfusion\.git.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string3 = /.{0,1000}\/PerfusionDll\.dll.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string4 = /.{0,1000}\[\!\]\sFailed\sto\sdelete\sPerformance\sregistry\skey\..{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string5 = /.{0,1000}\[\-\]\sFailed\sto\sdelete\sPerformance\sDLL.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string6 = /.{0,1000}\[\+\]\sExploit\scompleted\.\sGot\sa\sSYSTEM\stoken\!\s:\).{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string7 = /.{0,1000}\\Perfusion\.cpp.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string8 = /.{0,1000}\\Perfusion\.exe.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string9 = /.{0,1000}\\Perfusion\.sln.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string10 = /.{0,1000}\\PerfusionDll\.cpp.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string11 = /.{0,1000}\\PerfusionDll\.dll.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string12 = /.{0,1000}\\PerfusionDll\.log.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string13 = /.{0,1000}1B1F64B3\-B8A4\-4BBB\-BB66\-F020E2D4F288.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string14 = /.{0,1000}A7397316\-0AEF\-4379\-B285\-C276DE02BDE1.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string15 = /.{0,1000}C:\\Users\\.{0,1000}\\AppData\\Local\\Temp\\performance_636_3000_1\.dll.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string16 = /.{0,1000}https:\/\/itm4n\.github\.io\/windows\-registry\-rpceptmapper\-eop\/.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string17 = /.{0,1000}itm4n\/Perfusion.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string18 = /.{0,1000}Perfusion\.exe\s\-c.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string19 = /.{0,1000}Perfusion\\RegistryPatch\.ps1.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string20 = /.{0,1000}Perfusion\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Exploit for the RpcEptMapper registry key permissions vulnerability (Windows 7 / 2088R2 / 8 / 2012)
        // Reference: https://github.com/itm4n/Perfusion
        $string21 = /.{0,1000}WritePayloadDll\(LPWSTR\spwszDllPath\).{0,1000}/ nocase ascii wide

    condition:
        any of them
}
