rule macetrap
{
    meta:
        description = "Detection patterns for the tool 'macetrap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macetrap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MaceTrap is a proof-of-concept for time stomping using SetFileTime. MaceTrap allows you to set the CreationTime / LastAccessTime / LastWriteTime for arbitrary files and folders
        // Reference: https://github.com/FuzzySecurity/Sharp-Suite/tree/master/MaceTrap
        $string1 = /MaceTrap\.exe/ nocase ascii wide

    condition:
        any of them
}
