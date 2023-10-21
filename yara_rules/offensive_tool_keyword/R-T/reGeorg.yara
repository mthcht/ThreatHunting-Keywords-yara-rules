rule reGeorg
{
    meta:
        description = "Detection patterns for the tool 'reGeorg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reGeorg"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string1 = /\/reGeorg\.git/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string2 = /reGeorg\-master/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string3 = /reGeorgSocksProxy\.py/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string4 = /sensepost\/reGeorg/ nocase ascii wide

    condition:
        any of them
}