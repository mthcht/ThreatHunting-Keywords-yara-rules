rule kalitorify
{
    meta:
        description = "Detection patterns for the tool 'kalitorify' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kalitorify"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: kalitorify is a shell script for Kali Linux which use iptables settings to create a Transparent Proxy through the Tor Network. the program also allows you to perform various checks like checking the Tor Exit Node (i.e. your public IP when you are under Tor proxy). or if Tor has been configured correctly checking service and network settings.
        // Reference: https://github.com/brainfucksec/kalitorify
        $string1 = /kalitorify/ nocase ascii wide

    condition:
        any of them
}
