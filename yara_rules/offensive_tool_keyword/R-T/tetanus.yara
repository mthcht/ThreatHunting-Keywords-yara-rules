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
        $string1 = /.{0,1000}\.\/mythic\-cli\s.{0,1000}/ nocase ascii wide
        // Description: Mythic C2 agent targeting Linux and Windows hosts written in Rust
        // Reference: https://github.com/MythicAgents/tetanus
        $string2 = /.{0,1000}MythicAgents\/tetanus.{0,1000}/ nocase ascii wide
        // Description: Mythic C2 agent targeting Linux and Windows hosts written in Rust
        // Reference: https://github.com/MythicAgents/tetanus
        $string3 = /.{0,1000}payload\sstart\stetanus.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
