rule javascript_obfuscator
{
    meta:
        description = "Detection patterns for the tool 'javascript-obfuscator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "javascript-obfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: JavaScript Obfuscator is a powerful free obfuscator for JavaScript. containing a variety of features which provide protection for your source code.
        // Reference: https://github.com/javascript-obfuscator/javascript-obfuscator
        $string1 = /javascript\-obfuscator/ nocase ascii wide

    condition:
        any of them
}
