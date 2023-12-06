rule mitmsocks4j
{
    meta:
        description = "Detection patterns for the tool 'mitmsocks4j' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmsocks4j"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Man-in-the-middle SOCKS Proxy
        // Reference: https://github.com/Akdeniz/mitmsocks4j
        $string1 = /mitmsocks/ nocase ascii wide
        // Description: Man-in-the-middle SOCKS Proxy for Java
        // Reference: https://github.com/Akdeniz/mitmsocks4j
        $string2 = /mitmsocks4j/ nocase ascii wide

    condition:
        any of them
}
