rule LALIN
{
    meta:
        description = "Detection patterns for the tool 'LALIN' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LALIN"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: this script automatically install any package for pentest with uptodate tools . and lazy command for run the tools like lazynmap . install another and update to new
        // Reference: https://github.com/screetsec/LALIN
        $string1 = /.{0,1000}\sLalin\.sh.{0,1000}/ nocase ascii wide
        // Description: this script automatically install any package for pentest with uptodate tools . and lazy command for run the tools like lazynmap . install another and update to new
        // Reference: https://github.com/screetsec/LALIN
        $string2 = /.{0,1000}\.\/Lalin\.sh.{0,1000}/ nocase ascii wide
        // Description: this script automatically install any package for pentest with uptodate tools . and lazy command for run the tools like lazynmap . install another and update to new
        // Reference: https://github.com/screetsec/LALIN
        $string3 = /.{0,1000}Lalin\.sh\s.{0,1000}/ nocase ascii wide
        // Description: this script automatically install any package for pentest with uptodate tools . and lazy command for run the tools like lazynmap . install another and update to new
        // Reference: https://github.com/screetsec/LALIN
        $string4 = /.{0,1000}lazynmap\.sh.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
