rule DumpsterFire
{
    meta:
        description = "Detection patterns for the tool 'DumpsterFire' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DumpsterFire"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The DumpsterFire Toolset is a modular. menu-driven. cross-platform tool for building repeatable. time-delayed. distributed security events. Easily create custom event chains for Blue Team drills and sensor / alert mapping. Red Teams can create decoy incidents. distractions. and lures to support and scale their operations. Turn paper tabletop exercises into controlled live fire range events. Build event sequences (narratives) to simulate realistic scenarios and generate corresponding network and filesystem artifacts.
        // Reference: https://github.com/TryCatchHCF/DumpsterFire
        $string1 = /\/DumpsterFire\// nocase ascii wide

    condition:
        any of them
}
