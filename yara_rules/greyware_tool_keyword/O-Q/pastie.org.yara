rule pastie_org
{
    meta:
        description = "Detection patterns for the tool 'pastie.org' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pastie.org"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: accessing paste raw content
        // Reference: http://pastie.org/
        $string1 = /http\:\/\/pastie\.org\/p\/.{0,1000}\/raw/ nocase ascii wide
        // Description: sending data to a pastebin
        // Reference: http://pastie.org/
        $string2 = /http\:\/\/pastie\.org\/pastes\/create/ nocase ascii wide

    condition:
        any of them
}
