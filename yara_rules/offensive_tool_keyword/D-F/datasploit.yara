rule datasploit
{
    meta:
        description = "Detection patterns for the tool 'datasploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "datasploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Performs OSINT on a domain / email / username / phone and find out information from different sources
        // Reference: https://github.com/dvopsway/datasploit
        $string1 = /DataSploit/ nocase ascii wide

    condition:
        any of them
}
