rule Rock_ON
{
    meta:
        description = "Detection patterns for the tool 'Rock-ON' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Rock-ON"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Rock-On is a all in one recon tool that will help your Recon process give a boost. It is mainley aimed to automate the whole process of recon and save the time that is being wasted in doing all this stuffs manually. A thorough blog will be up in sometime. Stay tuned for the Stable version with a UI
        // Reference: https://github.com/SilverPoision/Rock-ON
        $string1 = /SilverPoision\/Rock\-ON/ nocase ascii wide

    condition:
        any of them
}
