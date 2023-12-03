rule elastic_agent
{
    meta:
        description = "Detection patterns for the tool 'elastic-agent' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elastic-agent"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: uninstall elast-agent from the system
        // Reference: N/A
        $string1 = /.{0,1000}elastic\-agent\.exe\suninstall.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
