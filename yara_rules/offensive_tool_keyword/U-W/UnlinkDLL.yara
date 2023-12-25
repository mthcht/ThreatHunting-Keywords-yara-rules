rule UnlinkDLL
{
    meta:
        description = "Detection patterns for the tool 'UnlinkDLL' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UnlinkDLL"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string1 = /\/UnlinkDLL\.git/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string2 = /frkngksl\/UnlinkDLL/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string3 = /listdlls64\.exe/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string4 = /MaliciousInjectedDll\.dll/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string5 = /UnlinkDLL\.exe/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string6 = /UnlinkDLL\\Main\.nim/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string7 = /UnlinkDLL\\Structs\.nim/ nocase ascii wide
        // Description: DLL Unlinking from InLoadOrderModuleList - InMemoryOrderModuleList - InInitializationOrderModuleList and LdrpHashTable
        // Reference: https://github.com/frkngksl/UnlinkDLL
        $string8 = /UnlinkDLL\-main/ nocase ascii wide

    condition:
        any of them
}
