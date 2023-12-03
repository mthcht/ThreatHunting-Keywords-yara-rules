rule reverse_shell_generator
{
    meta:
        description = "Detection patterns for the tool 'reverse-shell-generator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "reverse-shell-generator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hosted Reverse Shell generator with a ton of functionality
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string1 = /.{0,1000}\sreverse_shell_generator.{0,1000}/ nocase ascii wide
        // Description: Hosted Reverse Shell generator with a ton of functionality
        // Reference: https://github.com/0dayCTF/reverse-shell-generator
        $string2 = /.{0,1000}\/reverse\-shell\-generator.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
