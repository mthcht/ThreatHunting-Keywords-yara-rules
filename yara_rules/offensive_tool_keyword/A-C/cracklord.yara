rule cracklord
{
    meta:
        description = "Detection patterns for the tool 'cracklord' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cracklord"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string1 = /\/cracklord\.git/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string2 = /\/cracklord\/cmd\// nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string3 = /cracklord\-master\./ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string4 = /cracklord\-queued.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string5 = /cracklord\-resourced.{0,1000}_amd64\.deb/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string6 = /jmmcatee\/cracklord/ nocase ascii wide

    condition:
        any of them
}
