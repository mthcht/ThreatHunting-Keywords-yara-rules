rule burrow
{
    meta:
        description = "Detection patterns for the tool 'burrow' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "burrow"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Expose localhost to the internet using a public URL
        // Reference: https://burrow.io
        $string1 = /https\:\/\/burrow\.io\/.{0,1000}\s\|\sbash\s/ nocase ascii wide
        // Description: Expose localhost to the internet using a public URL
        // Reference: https://burrow.io
        $string2 = /https\:\/\/burrow\.io\/tunnels/ nocase ascii wide

    condition:
        any of them
}
