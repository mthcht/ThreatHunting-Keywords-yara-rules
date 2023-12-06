rule onionscan
{
    meta:
        description = "Detection patterns for the tool 'onionscan' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onionscan"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: OnionScan has two primary goals: We want to help operators of hidden services find and fix operational security issues with their services. We want to help them detect misconfigurations and we want to inspire a new generation of anonymity engineering projects to help make the world a more private place. Secondly we want to help researchers and investigators monitor and track Dark Web sites. In fact we want to make this as easy as possible. Not because we agree with the goals and motives of every investigation force out there - most often we don't. But by making these kinds of investigations easy. we hope to create a powerful incentive for new anonymity technology
        // Reference: https://onionscan.org/
        $string1 = /OnionScan/ nocase ascii wide

    condition:
        any of them
}
