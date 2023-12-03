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
        $string1 = /.{0,1000}\/PrivExchange\.git.{0,1000}/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string2 = /.{0,1000}dirkjanm\/PrivExchange.{0,1000}/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string3 = /.{0,1000}httpattack\.py.{0,1000}/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string4 = /.{0,1000}privexchange\.py.{0,1000}/ nocase ascii wide
        // Description: Exchange your privileges for Domain Admin privs by abusing Exchange
        // Reference: https://github.com/dirkjanm/PrivExchange
        $string5 = /.{0,1000}PrivExchange\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
