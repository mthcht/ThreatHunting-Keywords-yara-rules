rule tetanus
{
    meta:
        description = "Detection patterns for the tool 'tetanus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tetanus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mythic C2 agent targeting Linux and Windows hosts written in Rust
        // Reference: https://github.com/MythicAgents/tetanus
        $string1 = /\.\/mythic\-cli\s/ nocase ascii wide
        // Description: Mythic C2 agent targeting Linux and Windows hosts written in Rust
        // Reference: https://github.com/MythicAgents/tetanus
        $string2 = /MythicAgents\/tetanus/ nocase ascii wide
        // Description: Mythic C2 agent targeting Linux and Windows hosts written in Rust
        // Reference: https://github.com/MythicAgents/tetanus
        $string3 = /payload\sstart\stetanus/ nocase ascii wide

    condition:
        any of them
}
