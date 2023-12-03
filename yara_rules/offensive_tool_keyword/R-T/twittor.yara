rule twittor
{
    meta:
        description = "Detection patterns for the tool 'twittor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "twittor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string1 = /.{0,1000}\/twittor\.git.{0,1000}/ nocase ascii wide
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string2 = /.{0,1000}PaulSec\/twittor.{0,1000}/ nocase ascii wide
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string3 = /.{0,1000}twittor\.py.{0,1000}/ nocase ascii wide
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string4 = /.{0,1000}twittor\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
