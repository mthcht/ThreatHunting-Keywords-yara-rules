rule p0wny_shell
{
    meta:
        description = "Detection patterns for the tool 'p0wny-shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "p0wny-shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: p0wny@shell:~# is a very basic. single-file. PHP shell. It can be used to quickly execute commands on a server when pentesting a PHP application. Use it with caution: this script represents a security risk for the server.
        // Reference: https://github.com/flozz/p0wny-shell
        $string1 = /.{0,1000}p0wny\-shell.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
