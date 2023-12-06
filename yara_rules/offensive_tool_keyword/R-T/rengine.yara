rule rengine
{
    meta:
        description = "Detection patterns for the tool 'rengine' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rengine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reNgine is an automated reconnaissance framework for web applications with a focus on highly configurable streamlined recon process via Engines recon data correlation and organization continuous monitoring backed by a database and simple yet intuitive User Interface. reNgine makes it easy for penetration testers to gather reconnaissance with
        // Reference: https://github.com/yogeshojha/rengine
        $string1 = /yogeshojha\/rengine/ nocase ascii wide

    condition:
        any of them
}
