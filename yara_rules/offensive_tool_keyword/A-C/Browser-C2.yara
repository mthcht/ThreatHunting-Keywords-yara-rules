rule Browser_C2
{
    meta:
        description = "Detection patterns for the tool 'Browser-C2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-C2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Post Exploitation agent which uses a browser to do C2 operations.
        // Reference: https://github.com/0x09AL/Browser-C2
        $string1 = /\/Browser\-C2/ nocase ascii wide
        // Description: Post Exploitation agent which uses a browser to do C2 operations.
        // Reference: https://github.com/0x09AL/Browser-C2
        $string2 = /Browser\-C2\.git/ nocase ascii wide
        // Description: Post Exploitation agent which uses a browser to do C2 operations.
        // Reference: https://github.com/0x09AL/Browser-C2
        $string3 = /Browser\-C2\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
