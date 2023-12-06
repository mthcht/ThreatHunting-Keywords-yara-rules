rule XXEinjector
{
    meta:
        description = "Detection patterns for the tool 'XXEinjector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "XXEinjector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.
        // Reference: https://github.com/enjoiz/XXEinjector
        $string1 = /XXEinjector/ nocase ascii wide

    condition:
        any of them
}
