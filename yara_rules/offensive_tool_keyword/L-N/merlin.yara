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
        $string1 = /.{0,1000}\/merlin\.html.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string2 = /.{0,1000}\/merlin\.js.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string3 = /.{0,1000}merlinAgent\-.{0,1000}\.7z.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string4 = /.{0,1000}merlinAgent\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string5 = /.{0,1000}merlinAgent\-Darwin\-.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string6 = /.{0,1000}merlinAgent\-Linux\-.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string7 = /.{0,1000}merlinServer\-.{0,1000}\.7z.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string8 = /.{0,1000}merlinServer\-.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string9 = /.{0,1000}merlinServer\-Linux.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string10 = /.{0,1000}Ne0nd0g\/merlin.{0,1000}/ nocase ascii wide
        // Description: Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang.
        // Reference: https://github.com/Ne0nd0g/merlin
        $string11 = /.{0,1000}toteslegit\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
