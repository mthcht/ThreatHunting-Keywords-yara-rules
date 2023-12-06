rule awesome_osint
{
    meta:
        description = "Detection patterns for the tool 'awesome-osint' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "awesome-osint"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A curated list of amazingly awesome open source intelligence tools and resources. Open-source intelligence (OSINT) is intelligence collected from publicly available sources. In the intelligence community (IC). the term open refers to overt. publicly available sources (as opposed to covert or clandestine sources)
        // Reference: https://github.com/jivoi/awesome-osint
        $string1 = /awesome\-osint/ nocase ascii wide

    condition:
        any of them
}
