rule nirsoft
{
    meta:
        description = "Detection patterns for the tool 'nirsoft' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nirsoft"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: designed to capture webcam images
        // Reference: https://medium.com/checkmarx-security/python-obfuscation-traps-1acced941375
        $string1 = /https\:\/\/www\.nirsoft\.net\/utils\/webcamimagesave\.zip/ nocase ascii wide

    condition:
        any of them
}
