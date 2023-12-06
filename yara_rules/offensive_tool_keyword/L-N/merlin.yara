rule merlin
{
    meta:
        description = "Detection patterns for the tool 'merlin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string1 = /\/merlin\.html/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string2 = /\/merlin\.js/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string3 = /merlinAgent\-.{0,1000}\.7z/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string4 = /merlinAgent\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string5 = /merlinAgent\-Darwin\-/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string6 = /merlinAgent\-Linux\-/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string7 = /merlinServer\-.{0,1000}\.7z/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string8 = /merlinServer\-.{0,1000}\.exe/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string9 = /merlinServer\-Linux/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string10 = /Ne0nd0g\/merlin/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string11 = /toteslegit\.ps1/ nocase ascii wide

    condition:
        any of them
}
