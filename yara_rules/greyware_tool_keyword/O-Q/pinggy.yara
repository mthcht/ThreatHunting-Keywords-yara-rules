rule pinggy
{
    meta:
        description = "Detection patterns for the tool 'pinggy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pinggy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Create HTTP/TCP or TLS tunnels to your Mac/PC. Even if it is sitting behind firewalls and NATs.
        // Reference: https://pinggy.io/
        $string1 = /\sa\.pinggy\.io/ nocase ascii wide
        // Description: Create HTTP/TCP or TLS tunnels to your Mac/PC. Even if it is sitting behind firewalls and NATs.
        // Reference: https://pinggy.io/
        $string2 = /\.a\.pinggy\.online/ nocase ascii wide
        // Description: Create HTTP/TCP or TLS tunnels to your Mac/PC. Even if it is sitting behind firewalls and NATs.
        // Reference: https://pinggy.io/
        $string3 = /\.free\.pinggy\.online/ nocase ascii wide
        // Description: Create HTTP/TCP or TLS tunnels to your Mac/PC. Even if it is sitting behind firewalls and NATs.
        // Reference: https://pinggy.io/
        $string4 = /\/a\.pinggy\.io/ nocase ascii wide
        // Description: Create HTTP/TCP or TLS tunnels to your Mac/PC. Even if it is sitting behind firewalls and NATs.
        // Reference: https://pinggy.io/
        $string5 = /\@a\.pinggy\.io/ nocase ascii wide

    condition:
        any of them
}
