rule redis_rce
{
    meta:
        description = "Detection patterns for the tool 'redis-rce' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "redis-rce"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A exploit for Redis 4.x/5.x RCE. inspired by Redis post-exploitation.
        // Reference: https://github.com/Ridter/redis-rce
        $string1 = /redis\-rce/ nocase ascii wide

    condition:
        any of them
}
