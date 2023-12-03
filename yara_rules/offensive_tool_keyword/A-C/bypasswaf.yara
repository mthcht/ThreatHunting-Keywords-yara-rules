rule bypasswaf
{
    meta:
        description = "Detection patterns for the tool 'bypasswaf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bypasswaf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Add headers to all Burp requests to bypass some WAF products
        // Reference: https://github.com/codewatchorg/bypasswaf
        $string1 = /.{0,1000}bypasswaf\.jar.{0,1000}/ nocase ascii wide
        // Description: Add headers to all Burp requests to bypass some WAF products
        // Reference: https://github.com/codewatchorg/bypasswaf
        $string2 = /.{0,1000}bypasswaf\.py.{0,1000}/ nocase ascii wide
        // Description: Add headers to all Burp requests to bypass some WAF products
        // Reference: https://github.com/codewatchorg/bypasswaf
        $string3 = /.{0,1000}codewatchorg\/bypasswaf.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
