rule privexchange
{
    meta:
        description = "Detection patterns for the tool 'privexchange' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "privexchange"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string1 = /\/PrivExchange\.git/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string2 = /dirkjanm\/PrivExchange/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string3 = /httpattack\.py/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string4 = /privexchange\.py/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string5 = /PrivExchange\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
