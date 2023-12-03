rule DockerPwn
{
    meta:
        description = "Detection patterns for the tool 'DockerPwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DockerPwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automation for abusing an exposed Docker TCP Socket. 
        // Reference: https://github.com/AbsoZed/DockerPwn.py
        $string1 = /.{0,1000}DockerPwn.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
