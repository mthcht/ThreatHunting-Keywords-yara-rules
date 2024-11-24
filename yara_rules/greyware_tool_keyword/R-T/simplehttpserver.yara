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
        $string1 = " -m SimpleHTTPServer " nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string2 = "import SimpleHTTPServer" nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string3 = "python -m SimpleHTTPServer" nocase ascii wide
        // Description: quick web server in python
        // Reference: https://docs.python.org/2/library/simplehttpserver.html
        $string4 = /SimpleHTTPServer\.SimpleHTTPRequestHandler/ nocase ascii wide

    condition:
        any of them
}
