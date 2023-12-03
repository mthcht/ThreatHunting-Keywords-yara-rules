rule ImplantSSP
{
    meta:
        description = "Detection patterns for the tool 'ImplantSSP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ImplantSSP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string1 = /.{0,1000}\sImplantSSP\.exe.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string2 = /.{0,1000}\/ImplantSSP\.exe.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string3 = /.{0,1000}\[\+\]\sAdding\syour\sDLL\sto\sthe\sLSA\sSecurity\sPackages\sregistry\skey.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string4 = /.{0,1000}\[\+\]\sRegistry\skey\sset\.\sDLL\swill\sbe\sloaded\son\sreboot.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string5 = /.{0,1000}\[\+\]\sSafety\schecks\spassed\.\sImplanting\syour\sDLL.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string6 = /.{0,1000}\\ImplantSSP\.exe.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string7 = /.{0,1000}ImplantSSP\.csproj.{0,1000}/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string8 = /.{0,1000}master\/ImplantSSP\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
