rule SystemBC
{
    meta:
        description = "Detection patterns for the tool 'SystemBC' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SystemBC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: multifunctional malware mostly known as a socks proxy - used by varius ransomware groups with additional functionnalities
        // Reference: https://github.com/Leeon123/Python3-botnet
        $string1 = /\/tmp\/socks5\.sh/

    condition:
        any of them
}
