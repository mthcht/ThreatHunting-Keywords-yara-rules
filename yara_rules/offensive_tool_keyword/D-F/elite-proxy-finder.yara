rule elite_proxy_finder
{
    meta:
        description = "Detection patterns for the tool 'elite-proxy-finder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "elite-proxy-finder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Finds elite anonymity (L1) HTTP proxies then tests them all in parallel. Tests each proxy against 3 IP checking URLs including one which is HTTPS to make sure it can handle HTTPS requests. Then checks the proxy headers to confirm its an elite L1 proxy that will not leak any extra info. By default the script will only print the proxy IP. request time. and country code of proxies that pass all four tests but you can see all the results including errors in any of the tests with the -a (--all) option.
        // Reference: https://github.com/DanMcInerney/elite-proxy-finder
        $string1 = /elite\-proxy\-finder/ nocase ascii wide

    condition:
        any of them
}
