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
        $string1 = /\.\.\.\severy\soffice\sneeds\sa\stool\slike\sGeorg/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string2 = /\/reGeorg\.git/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string3 = /\/tunnel\.nosocket\.php/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string4 = /\/tunnel\.tomcat\.5\.jsp/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string5 = /Georg\sis\snot\sready\,\splease\scheck\surl/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string6 = /Georg\ssays\,\s\'All\sseems\sfine\'/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string7 = /reGeorg\-master/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string8 = /reGeorgSocksProxy\.py/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string9 = /sensepost\/reGeorg/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string10 = /Socks\sserver\sfor\sreGeorg\sHTTP\(s\)\stunneller/ nocase ascii wide
        // Description: The successor to reDuh - pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.
        // Reference: https://github.com/sensepost/reGeorg
        $string11 = /Starting\ssocks\sserver\s.{0,1000}\stunnel\sat\s/ nocase ascii wide

    condition:
        any of them
}
