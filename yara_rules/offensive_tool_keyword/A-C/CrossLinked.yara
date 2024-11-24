rule CrossLinked
{
    meta:
        description = "Detection patterns for the tool 'CrossLinked' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CrossLinked"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CrossLinked simplifies the processes of searching LinkedIn to collect valid employee names when performing password spraying or other security testing against an organization. Using similar search engine scraping capabilities found in tools like subscraper and pymeta
        // Reference: https://github.com/m8r0wn/CrossLinked
        $string1 = "CrossLinked" nocase ascii wide

    condition:
        any of them
}
