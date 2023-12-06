rule BlockWindows
{
    meta:
        description = "Detection patterns for the tool 'BlockWindows' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BlockWindows"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Stop Windows 7 through 10 Nagging and Spying updates. Tasks. IPs. and services. Works with Windows 7 through 10
        // Reference: https://github.com/WindowsLies/BlockWindows
        $string1 = /WindowsLies.{0,1000}BlockWindows/ nocase ascii wide

    condition:
        any of them
}
