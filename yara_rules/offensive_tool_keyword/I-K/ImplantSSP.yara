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
        $string1 = /\sImplantSSP\.exe/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string2 = /\/ImplantSSP\.exe/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string3 = /\[\+\]\sAdding\syour\sDLL\sto\sthe\sLSA\sSecurity\sPackages\sregistry\skey/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string4 = /\[\+\]\sRegistry\skey\sset\.\sDLL\swill\sbe\sloaded\son\sreboot/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string5 = /\[\+\]\sSafety\schecks\spassed\.\sImplanting\syour\sDLL/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string6 = /\\ImplantSSP\.exe/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string7 = /ImplantSSP\.csproj/ nocase ascii wide
        // Description: Installs a user-supplied Security Support Provider (SSP) DLL on the system which will be loaded by LSA on system start
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/ImplantSSP
        $string8 = /master\/ImplantSSP\// nocase ascii wide

    condition:
        any of them
}
