rule wordsmith
{
    meta:
        description = "Detection patterns for the tool 'wordsmith' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wordsmith"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The aim of Wordsmith is to assist with creating tailored wordlists and usernames that are primarilly based on geolocation.
        // Reference: https://github.com/skahwah/wordsmith
        $string1 = /skahwah.{0,1000}wordsmith/ nocase ascii wide

    condition:
        any of them
}
