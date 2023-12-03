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
        $string1 = /.{0,1000}\/GadgetToJScript\.git.{0,1000}/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string2 = /.{0,1000}\\shellcode_loader\.dll.{0,1000}/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string3 = /.{0,1000}AF9C62A1\-F8D2\-4BE0\-B019\-0A7873E81EA9.{0,1000}/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string4 = /.{0,1000}GadgetToJScript\.csproj.{0,1000}/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string5 = /.{0,1000}GadgetToJScript\.sln.{0,1000}/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string6 = /.{0,1000}GadgetToJScript\-master.{0,1000}/ nocase ascii wide
        // Description: A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts.
        // Reference: https://github.com/med0x2e/GadgetToJScript
        $string7 = /.{0,1000}med0x2e\/GadgetToJScript.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
