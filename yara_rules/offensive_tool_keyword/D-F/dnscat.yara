rule dnscat
{
    meta:
        description = "Detection patterns for the tool 'dnscat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Welcome to dnscat2. a DNS tunnel that WON'T make you sick and kill you This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol. which is an effective tunnel out of almost every network.
        // Reference: https://github.com/iagox86/dnscat2
        $string1 = /.{0,1000}dnscat.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
