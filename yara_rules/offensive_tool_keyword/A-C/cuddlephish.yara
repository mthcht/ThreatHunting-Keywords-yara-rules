rule cuddlephish
{
    meta:
        description = "Detection patterns for the tool 'cuddlephish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cuddlephish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string1 = /\/cuddlephish\.git/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string2 = /\/cuddlephish\.html/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string3 = /\/user_data\/.{0,1000}\/keylog\.txt/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string4 = /57a0a978ab19598abf7185762834fef1b4dbd4db30d2fb85d411a0e22821df25/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string5 = /AAABAAMAEBAAAAEAIABoBAAANgAAACAgAAABACAAKBEAAJ4EAAAwMAAAAQAgAGgmAADGFQAAKAAAABAAAAAgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP39/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string6 = /browser\.keylog_file\.write/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string7 = /cuddlephish.{0,1000}stealer\.js/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string8 = /cuddlephish\-main/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string9 = /fkasler\/cuddlephish/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string10 = /http\:\/\/localhost\:58082\/broadcast\?id\=/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string11 = /listen\(58082.{0,1000}\s\'0\.0\.0\.0\'/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string12 = /node\sstealer\.js\s/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string13 = /ws\:\/\/localhost\:58082/ nocase ascii wide

    condition:
        any of them
}
