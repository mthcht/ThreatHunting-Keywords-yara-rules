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
        $string1 = /.{0,1000}\/cuddlephish\.git.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string2 = /.{0,1000}\/cuddlephish\.html.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string3 = /.{0,1000}\/user_data\/.{0,1000}\/keylog\.txt.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string4 = /.{0,1000}AAABAAMAEBAAAAEAIABoBAAANgAAACAgAAABACAAKBEAAJ4EAAAwMAAAAQAgAGgmAADGFQAAKAAAABAAAAAgAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP39.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string5 = /.{0,1000}browser\.keylog_file\.write.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string6 = /.{0,1000}cuddlephish.{0,1000}stealer\.js/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string7 = /.{0,1000}cuddlephish\-main.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string8 = /.{0,1000}fkasler\/cuddlephish.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string9 = /.{0,1000}http:\/\/localhost:58082\/broadcast\?id\=.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string10 = /.{0,1000}listen\(58082.{0,1000}\s\'0\.0\.0\.0\'.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string11 = /.{0,1000}node\sstealer\.js\s.{0,1000}/ nocase ascii wide
        // Description: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers
        // Reference: https://github.com/fkasler/cuddlephish
        $string12 = /.{0,1000}ws:\/\/localhost:58082.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
