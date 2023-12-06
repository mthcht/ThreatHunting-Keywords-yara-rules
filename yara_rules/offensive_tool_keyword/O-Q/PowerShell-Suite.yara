rule PowerShell_Suite
{
    meta:
        description = "Detection patterns for the tool 'PowerShell-Suite' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShell-Suite"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: There are great tools and resources online to accomplish most any task in PowerShell. sometimes however. there is a need to script together a util for a specific purpose or to bridge an ontological gap. This is a collection of PowerShell utilities I put together either for fun or because I had a narrow application in mind.
        // Reference: https://github.com/FuzzySecurity/PowerShell-Suite
        $string1 = /PowerShell\-Suite/ nocase ascii wide

    condition:
        any of them
}
