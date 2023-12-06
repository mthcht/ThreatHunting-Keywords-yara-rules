rule Airbash
{
    meta:
        description = "Detection patterns for the tool 'Airbash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Airbash"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A POSIX-compliant fully automated WPA PSK handshake capture script aimed at penetration testing.
        // Reference: https://github.com/tehw0lf/airbash
        $string1 = /Airbash/ nocase ascii wide

    condition:
        any of them
}
