rule ruby
{
    meta:
        description = "Detection patterns for the tool 'ruby' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ruby"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: ruby reverse shell
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /ruby\s\-rsocket\s.{0,1000}TCPSocket\.open\(.{0,1000}exec\ssprintf.{0,1000}\/bin\/sh\s\-i\s/ nocase ascii wide

    condition:
        any of them
}
