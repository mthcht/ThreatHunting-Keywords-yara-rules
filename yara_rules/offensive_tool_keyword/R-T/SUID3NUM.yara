rule SUID3NUM
{
    meta:
        description = "Detection patterns for the tool 'SUID3NUM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SUID3NUM"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A standalone python2/3 script which utilizes pythons built-in modules to find SUID bins. separate default bins from custom bins. cross-match those with bins in GTFO Bins repository & auto-exploit those. all with colors! ( ?? ?? ??)
        // Reference: https://github.com/Anon-Exploiter/SUID3NUM
        $string1 = /SUID3NUM\s\-/ nocase ascii wide

    condition:
        any of them
}
