rule php
{
    meta:
        description = "Detection patterns for the tool 'php' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "php"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: php reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /php\s\-r\s.{0,1000}\$sock\=fsockopen\(.{0,1000}exec\(.{0,1000}\/bin\/sh\s\-i\s\<\&3\s\>\&3\s2\>\&3/ nocase ascii wide

    condition:
        any of them
}
