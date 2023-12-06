rule Biu_framework
{
    meta:
        description = "Detection patterns for the tool 'Biu-framework' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Biu-framework"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Biu-framework Security Scan Framework For Enterprise Intranet Based Services
        // Reference: https://awesomeopensource.com/project/0xbug/Biu-framework
        $string1 = /Biu\-framework/ nocase ascii wide

    condition:
        any of them
}
