rule linux
{
    meta:
        description = "Detection patterns for the tool 'linux' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linux"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: fork bomb linux - denial-of-service attack wherein a process continually replicates itself to deplete available system resources slowing down or crashing the system due to resource starvation
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs
        $string1 = /\:\(\)\{\:I\:\s\&I/ nocase ascii wide

    condition:
        any of them
}
