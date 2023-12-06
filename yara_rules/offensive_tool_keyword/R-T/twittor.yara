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
        $string1 = /\/twittor\.git/ nocase ascii wide
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string2 = /PaulSec\/twittor/ nocase ascii wide
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string3 = /twittor\.py/ nocase ascii wide
        // Description: A fully featured backdoor that uses Twitter as a C&C server 
        // Reference: https://github.com/PaulSec/twittor
        $string4 = /twittor\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
