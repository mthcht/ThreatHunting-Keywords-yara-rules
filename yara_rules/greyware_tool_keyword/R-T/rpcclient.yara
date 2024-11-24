rule rpcclient
{
    meta:
        description = "Detection patterns for the tool 'rpcclient' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rpcclient"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tool for executing client side MS-RPC functions (NULL session)
        // Reference: https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html
        $string1 = "rpcclient -U \"\" " nocase ascii wide

    condition:
        any of them
}
