rule StayKit
{
    meta:
        description = "Detection patterns for the tool 'StayKit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StayKit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: StayKit - Cobalt Strike persistence kit - StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string1 = /\/0xthirteen\/StayKit/ nocase ascii wide
        // Description: StayKit - Cobalt Strike persistence kit - StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string2 = /BackdoorLNK/ nocase ascii wide
        // Description: StayKit - Cobalt Strike persistence kit - StayKit is an extension for Cobalt Strike persistence by leveraging the execute_assembly function with the SharpStay .NET assembly. The aggressor script handles payload creation by reading the template files for a specific execution type.
        // Reference: https://github.com/0xthirteen/StayKit
        $string3 = /StayKit\.cna/ nocase ascii wide

    condition:
        any of them
}
