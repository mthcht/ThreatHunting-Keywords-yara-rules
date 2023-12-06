rule OSCP_Archives
{
    meta:
        description = "Detection patterns for the tool 'OSCP-Archives' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "OSCP-Archives"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: resources for red teamers 'During my journey to getting the OSCP. I always come across many articles. Git repo. videos. and other types of sources of great and valuable information that helps me during my studies. While having all of these in a bookmark folder is great. I wanted to also build a curated list of the resources that I've collected overtime. all in one area for everyone to access.'
        // Reference: https://github.com/CyDefUnicorn/OSCP-Archives
        $string1 = /OSCP\-Archives/ nocase ascii wide
        // Description: resources for red teamers 'During my journey to getting the OSCP. I always come across many articles. Git repo. videos. and other types of sources of great and valuable information that helps me during my studies. While having all of these in a bookmark folder is great. I wanted to also build a curated list of the resources that I've collected overtime. all in one area for everyone to access.'
        // Reference: https://github.com/CyDefUnicorn/OSCP-Archives
        $string2 = /scecli\\0evilpwfilter/ nocase ascii wide

    condition:
        any of them
}
