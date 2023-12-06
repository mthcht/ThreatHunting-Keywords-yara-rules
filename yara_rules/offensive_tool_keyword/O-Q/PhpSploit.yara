rule PhpSploit
{
    meta:
        description = "Detection patterns for the tool 'PhpSploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PhpSploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Full-featured C2 framework which silently persists on webserver via evil PHP oneliner
        // Reference: https://github.com/nil0x42/phpsploit
        $string1 = /PhpSploit/ nocase ascii wide

    condition:
        any of them
}
