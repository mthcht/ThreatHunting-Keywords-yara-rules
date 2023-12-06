rule https_portal
{
    meta:
        description = "Detection patterns for the tool 'https-portal' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "https-portal"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: HTTPS-PORTAL is a fully automated HTTPS server powered by Nginx. Lets Encrypt and Docker. By using it. you can run any existing web application over HTTPS. with only one extra line of configuration. The SSL certificates are obtained. and renewed from Lets Encrypt automatically.
        // Reference: https://github.com/SteveLTN/https-portal
        $string1 = /https\-portal/ nocase ascii wide

    condition:
        any of them
}
