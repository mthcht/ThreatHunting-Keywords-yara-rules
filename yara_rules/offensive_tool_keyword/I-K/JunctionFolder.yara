rule JunctionFolder
{
    meta:
        description = "Detection patterns for the tool 'JunctionFolder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "JunctionFolder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Creates a junction folder in the Windows Accessories Start Up folder as described in the Vault 7 leaks. On start or when a user browses the directory - the referenced DLL will be executed by verclsid.exe in medium integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/JunctionFolder
        $string1 = /.{0,1000}\%APPDATA\%\/Indexing\..{0,1000}/ nocase ascii wide
        // Description: Creates a junction folder in the Windows Accessories Start Up folder as described in the Vault 7 leaks. On start or when a user browses the directory - the referenced DLL will be executed by verclsid.exe in medium integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/JunctionFolder
        $string2 = /.{0,1000}\/master\/JunctionFolder\/.{0,1000}/ nocase ascii wide
        // Description: Creates a junction folder in the Windows Accessories Start Up folder as described in the Vault 7 leaks. On start or when a user browses the directory - the referenced DLL will be executed by verclsid.exe in medium integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/JunctionFolder
        $string3 = /.{0,1000}\\JunctionFolder\.csproj.{0,1000}/ nocase ascii wide
        // Description: Creates a junction folder in the Windows Accessories Start Up folder as described in the Vault 7 leaks. On start or when a user browses the directory - the referenced DLL will be executed by verclsid.exe in medium integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/JunctionFolder
        $string4 = /.{0,1000}C:\\Users\\.{0,1000}\\AppData\\Roaming\\Indexing\..{0,1000}/ nocase ascii wide
        // Description: Creates a junction folder in the Windows Accessories Start Up folder as described in the Vault 7 leaks. On start or when a user browses the directory - the referenced DLL will be executed by verclsid.exe in medium integrity.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/JunctionFolder
        $string5 = /.{0,1000}JunctionFolder\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
