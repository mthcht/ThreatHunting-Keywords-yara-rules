rule GadgetToJScript
{
    meta:
        description = "Detection patterns for the tool 'GadgetToJScript' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GadgetToJScript"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string1 = /\/GadgetToJScript\.git/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string2 = /\\shellcode_loader\.dll/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string3 = /AF9C62A1\-F8D2\-4BE0\-B019\-0A7873E81EA9/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string4 = /GadgetToJScript\.csproj/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string5 = /GadgetToJScript\.sln/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string6 = /GadgetToJScript\-master/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string7 = /med0x2e\/GadgetToJScript/ nocase ascii wide

    condition:
        any of them
}
