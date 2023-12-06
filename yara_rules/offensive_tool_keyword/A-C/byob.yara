rule byob
{
    meta:
        description = "Detection patterns for the tool 'byob' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "byob"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BYOB is an open-source post-exploitation framework for students. Pre-built C2 server Custom payload generator 12 post-exploitation modules It is designed to allow students and developers to easily implement their own code and add cool new features without having to write a C2 server or Remote Administration Tool from scratch
        // Reference: https://github.com/malwaredllc/byob
        $string1 = /malwaredllc/ nocase ascii wide

    condition:
        any of them
}
