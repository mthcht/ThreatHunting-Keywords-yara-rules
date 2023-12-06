rule fcrackzip
{
    meta:
        description = "Detection patterns for the tool 'fcrackzip' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fcrackzip"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: a Free/Fast Zip Password Cracker
        // Reference: https://manpages.ubuntu.com/manpages/trusty/man1/fcrackzip.1.html
        $string1 = /\/usr\/share\/wordlists\/.{0,1000}\.txt/ nocase ascii wide
        // Description: a Free/Fast Zip Password Cracker
        // Reference: https://manpages.ubuntu.com/manpages/trusty/man1/fcrackzip.1.html
        $string2 = /fcrackzip\s/ nocase ascii wide

    condition:
        any of them
}
