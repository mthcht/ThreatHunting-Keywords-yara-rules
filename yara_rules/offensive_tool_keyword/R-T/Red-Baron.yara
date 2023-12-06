rule Red_Baron
{
    meta:
        description = "Detection patterns for the tool 'Red-Baron' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Red-Baron"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Red Baron is a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient. disposable. secure and agile infrastructure for Red Teams.
        // Reference: https://github.com/byt3bl33d3r/Red-Baron
        $string1 = /Red\-Baron/ nocase ascii wide

    condition:
        any of them
}
