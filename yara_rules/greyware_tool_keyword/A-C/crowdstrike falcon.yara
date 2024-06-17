rule crowdstrike_falcon
{
    meta:
        description = "Detection patterns for the tool 'crowdstrike falcon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "crowdstrike falcon"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: suspicious commands executed remotly by crowdstrike agent
        // Reference: N/A
        $string1 = /runscript\s\-raw\=\`\`\`curl\s/ nocase ascii wide
        // Description: suspicious commands executed remotly by crowdstrike agent
        // Reference: N/A
        $string2 = /runscript\s\-raw\=\`\`\`whoami/ nocase ascii wide

    condition:
        any of them
}
