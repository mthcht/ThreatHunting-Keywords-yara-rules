rule sslstrip
{
    meta:
        description = "Detection patterns for the tool 'sslstrip' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sslstrip"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: sslstrip is a MITM tool that implements Moxie Marlinspikes SSL stripping attacks.
        // Reference: https://github.com/moxie0/sslstrip
        $string1 = /sslstrip/ nocase ascii wide

    condition:
        any of them
}
