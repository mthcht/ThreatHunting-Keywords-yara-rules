rule evilgrade
{
    meta:
        description = "Detection patterns for the tool 'evilgrade' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilgrade"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Evilgrade is a modular framework that allows the user to take advantage of poor upgrade implementations by injecting fake updates. It comes with pre-made binaries (agents). a working default configuration for fast pentests. and has its own WebServer and DNSServer modules. Easy to set up new settings. and has an autoconfiguration when new binary agents are set
        // Reference: https://github.com/infobyte/evilgrade
        $string1 = /evilgrade/ nocase ascii wide

    condition:
        any of them
}
