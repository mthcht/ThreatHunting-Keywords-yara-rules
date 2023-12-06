rule One_Lin3r
{
    meta:
        description = "Detection patterns for the tool 'One-Lin3r' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "One-Lin3r"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: One-Lin3r is simple modular and light-weight framework gives you all the one-liners that you will need while penetration testing (Windows. Linux. macOS or even BSD systems) or hacking generally with a lot of new features to make all of this fully automated (ex: you won't even need to copy the one-liners).
        // Reference: https://github.com/D4Vinci/One-Lin3r
        $string1 = /One\-Lin3r/ nocase ascii wide

    condition:
        any of them
}
