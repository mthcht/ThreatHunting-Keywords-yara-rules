rule w3af
{
    meta:
        description = "Detection patterns for the tool 'w3af' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "w3af"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: w3af is a Web Application Attack and Audit Framework. The projects goal is to create a framework to help you secure your web applications by finding and exploiting all web application vulnerabilities.
        // Reference: https://w3af.org/
        $string1 = /w3af_gui/ nocase ascii wide

    condition:
        any of them
}
