rule InspectAssembly
{
    meta:
        description = "Detection patterns for the tool 'InspectAssembly' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "InspectAssembly"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Inspect's a target .NET assembly's CIL for calls to deserializers and .NET remoting usage to aid in triaging potential privilege escalations.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/InspectAssembly
        $string1 = /InspectAssembly\.csproj/ nocase ascii wide
        // Description: Inspect's a target .NET assembly's CIL for calls to deserializers and .NET remoting usage to aid in triaging potential privilege escalations.
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/InspectAssembly
        $string2 = /InspectAssembly\.exe/ nocase ascii wide

    condition:
        any of them
}
