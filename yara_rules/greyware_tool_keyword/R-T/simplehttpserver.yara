rule simplehttpserver
{
    meta:
        description = "Detection patterns for the tool 'simplehttpserver' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "simplehttpserver"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string1 = /.{0,1000}\s\-m\sSimpleHTTPServer\s.{0,1000}/ nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string2 = /.{0,1000}import\sSimpleHTTPServer.{0,1000}/ nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string3 = /.{0,1000}python\s\-m\sSimpleHTTPServer.{0,1000}/ nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string4 = /.{0,1000}SimpleHTTPServer\.SimpleHTTPRequestHandler.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
