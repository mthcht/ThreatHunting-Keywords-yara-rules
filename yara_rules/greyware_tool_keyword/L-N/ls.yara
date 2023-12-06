rule ls
{
    meta:
        description = "Detection patterns for the tool 'ls' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ls"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: list remote pipename 
        // Reference: https://outflank.nl/blog/2023/10/19/listing-remote-named-pipes/
        $string1 = /ls\s\\\\1.{0,1000}\..{0,1000}\..{0,1000}\..{0,1000}\\IPC\$\\/ nocase ascii wide

    condition:
        any of them
}
