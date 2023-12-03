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
        $string1 = /.{0,1000}\/cracklord\.git.{0,1000}/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string2 = /.{0,1000}\/cracklord\/cmd\/.{0,1000}/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string3 = /.{0,1000}cracklord\-master\..{0,1000}/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string4 = /.{0,1000}cracklord\-queued.{0,1000}_amd64\.deb.{0,1000}/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string5 = /.{0,1000}cracklord\-resourced.{0,1000}_amd64\.deb.{0,1000}/ nocase ascii wide
        // Description: Queue and resource system for cracking passwords
        // Reference: https://github.com/jmmcatee/cracklord
        $string6 = /.{0,1000}jmmcatee\/cracklord.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
