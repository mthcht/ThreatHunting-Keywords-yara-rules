rule ShellPop
{
    meta:
        description = "Detection patterns for the tool 'ShellPop' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ShellPop"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shellpop is all about popping shells. With this tool you can generate easy and sophisticated reverse or bind shell commands to help you during penetration tests.
        // Reference: https://github.com/0x00-0x00/ShellPop
        $string1 = /\/ShellPop/ nocase ascii wide

    condition:
        any of them
}
