rule SharpSpray
{
    meta:
        description = "Detection patterns for the tool 'SharpSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This project is a C# port of my PowerSpray.ps1 script. SharpSpray a simple code set to perform a password spraying attack against all users of a domain using LDAP and is compatible with Cobalt Strike.
        // Reference: https://github.com/jnqpblc/SharpSpray
        $string1 = /SharpSpray/ nocase ascii wide

    condition:
        any of them
}