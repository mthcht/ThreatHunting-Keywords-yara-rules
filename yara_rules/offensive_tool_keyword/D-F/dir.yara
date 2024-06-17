rule dir
{
    meta:
        description = "Detection patterns for the tool 'dir' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dir"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: List Users with dir
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string1 = /dir\s\/b\s\/ad\s\"C\:\\Users\"/ nocase ascii wide
        // Description: Find the IDs of protected secrets for a specific user
        // Reference: https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference
        $string2 = /dir\sC\:\\Users\\.{0,1000}\\AppData\\Local\\Microsoft\\Credentials/ nocase ascii wide

    condition:
        any of them
}
