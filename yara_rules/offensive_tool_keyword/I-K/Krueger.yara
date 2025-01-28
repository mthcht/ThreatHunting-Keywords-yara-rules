rule Krueger
{
    meta:
        description = "Detection patterns for the tool 'Krueger' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Krueger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string1 = /\/Krueger\.exe/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string2 = /\/Krueger\.git/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string3 = /\@_logangoins\\n\@hullabrian/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string4 = /\\Krueger\.exe/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string5 = "022E5A85-D732-4C5D-8CAD-A367139068D8" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string6 = "783c942169fb6fe2dd984470a470440dd10a1aec09a153759e8d78a95096a8e6" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string7 = /ADMIN\$\\\\System32\\\\CodeIntegrity\\\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string8 = /ADMIN\$\\System32\\CodeIntegrity\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string9 = /C\$\\\\Windows\\\\System32\\\\CodeIntegrity\\\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string10 = /C\$\\Windows\\System32\\CodeIntegrity\\SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string11 = "d2a4f52a9923336f119a52e531bbb1e66f18322fd8efa9af1a64b94f4d36dc97" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string12 = "d6bd37f7c1bcc7ea255d46c3f8f07e6fd754f566dd05682584def7c8ba0aebf9" nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string13 = /Krueger\.SiPolicy\.p7b/ nocase ascii wide
        // Description: remotely killing EDR with WDAC
        // Reference: https://github.com/logangoins/Krueger
        $string14 = "logangoins/Krueger" nocase ascii wide

    condition:
        any of them
}
