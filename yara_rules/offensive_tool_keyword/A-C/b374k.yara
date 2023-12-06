rule b374k
{
    meta:
        description = "Detection patterns for the tool 'b374k' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "b374k"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This PHP Shell is a useful tool for system or web administrator to do remote management without using cpanel. connecting using ssh. ftp etc. All actions take place within a web browser
        // Reference: https://github.com/b374k/b374k
        $string1 = /\/B374K/ nocase ascii wide
        // Description: This PHP Shell is a useful tool for system or web administrator to do remote management without using cpanel. connecting using ssh. ftp etc. All actions take place within a web browser
        // Reference: https://github.com/b374k/b374k
        $string2 = /B374K.{0,1000}index\.php/ nocase ascii wide
        // Description: This PHP Shell is a useful tool for system or web administrator to do remote management without using cpanel. connecting using ssh. ftp etc. All actions take place within a web browser
        // Reference: https://github.com/b374k/b374k
        $string3 = /php\s\-f\s.{0,1000}\.php\s\-\-\s\-o\smyShell\.php/ nocase ascii wide

    condition:
        any of them
}
