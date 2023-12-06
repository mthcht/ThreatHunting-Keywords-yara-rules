rule mars_stealer
{
    meta:
        description = "Detection patterns for the tool 'mars stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mars stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Self-removal 'mars stealer' command
        // Reference: https://3xp0rt.com/posts/mars-stealer
        $string1 = /cmd\.exe\s\/c\stimeout\s\/t\s5\s\&\sdel\s\/f\s\/q\s.{0,1000}\%s.{0,1000}\s\&\sexit/ nocase ascii wide

    condition:
        any of them
}
