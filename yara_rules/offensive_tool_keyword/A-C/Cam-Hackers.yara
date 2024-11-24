rule Cam_Hackers
{
    meta:
        description = "Detection patterns for the tool 'Cam-Hackers' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cam-Hackers"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Hack Cameras CCTV FREE
        // Reference: https://github.com/AngelSecurityTeam/Cam-Hackers
        $string1 = /\/Cam\-Hackers\.git/ nocase ascii wide
        // Description: Hack Cameras CCTV FREE
        // Reference: https://github.com/AngelSecurityTeam/Cam-Hackers
        $string2 = "AngelSecurityTeam/Cam-Hackers" nocase ascii wide
        // Description: Hack Cameras CCTV FREE
        // Reference: https://github.com/AngelSecurityTeam/Cam-Hackers
        $string3 = /cam\-hackers\.py/ nocase ascii wide
        // Description: Hack Cameras CCTV FREE
        // Reference: https://github.com/AngelSecurityTeam/Cam-Hackers
        $string4 = /Cam\-Hackers\-master\.zip/ nocase ascii wide
        // Description: Hack Cameras CCTV FREE
        // Reference: https://github.com/AngelSecurityTeam/Cam-Hackers
        $string5 = /http\:\/\/www\.insecam\.org\/en\/jsoncountries\// nocase ascii wide

    condition:
        any of them
}
