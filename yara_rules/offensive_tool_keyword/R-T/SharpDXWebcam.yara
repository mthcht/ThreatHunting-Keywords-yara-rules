rule SharpDXWebcam
{
    meta:
        description = "Detection patterns for the tool 'SharpDXWebcam' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDXWebcam"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Utilizing DirectX and DShowNET assemblies to record video from a host's webcam
        // Reference: https://github.com/snovvcrash/SharpDXWebcam
        $string1 = /Get\-DXWebcamVideo\.ps1/ nocase ascii wide
        // Description: Utilizing DirectX and DShowNET assemblies to record video from a host's webcam
        // Reference: https://github.com/snovvcrash/SharpDXWebcam
        $string2 = /SharpDXWebcam/ nocase ascii wide

    condition:
        any of them
}
