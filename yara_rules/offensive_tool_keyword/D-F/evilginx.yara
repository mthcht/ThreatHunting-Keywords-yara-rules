rule evilginx
{
    meta:
        description = "Detection patterns for the tool 'evilginx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "evilginx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies. which in turn allows to bypass 2-factor authentication protection.This tool is a successor to Evilginx. released in 2017. which used a custom version of nginx HTTP server to provide man-in-the-middle functionality to act as a proxy between a browser and phished website. Present version is fully written in GO as a standalone application. which implements its own HTTP and DNS server. making it extremely easy to set up and use
        // Reference: https://github.com/kgretzky/evilginx2
        $string1 = /evilginx/ nocase ascii wide

    condition:
        any of them
}
