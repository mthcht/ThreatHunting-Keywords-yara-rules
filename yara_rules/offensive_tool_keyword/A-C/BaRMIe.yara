rule BaRMIe
{
    meta:
        description = "Detection patterns for the tool 'BaRMIe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BaRMIe"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BaRMIe is a tool for enumerating and attacking Java RMI (Remote Method Invocation) services.
        // Reference: https://github.com/NickstaDB/BaRMIe
        $string1 = /.{0,1000}BaRMIe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
