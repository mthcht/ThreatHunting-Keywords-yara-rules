rule CIMplant
{
    meta:
        description = "Detection patterns for the tool 'CIMplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CIMplant"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string1 = /\%SystemRoot\%\\\\MEMORY\.DMP/ nocase ascii wide
        // Description: C# port of WMImplant which uses either CIM or WMI to query remote systems
        // Reference: https://github.com/RedSiege/CIMplant
        $string2 = /C:\\Windows\\MEMORY\.DMP/ nocase ascii wide

    condition:
        any of them
}
