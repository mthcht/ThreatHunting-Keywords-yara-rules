rule sudo
{
    meta:
        description = "Detection patterns for the tool 'sudo' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sudo"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Sudo Persistence via sudoers file
        // Reference: https://github.com/RoseSecurity/Red-Teaming-TTPs/blob/main/Linux.md
        $string1 = /echo\s.*\%sudo\s\sALL\=\(ALL\)\sNOPASSWD:\sALL.*\s\>\>\s\/etc\/sudoers/ nocase ascii wide
        // Description: access sensitive files by abusing sudo permissions
        // Reference: N/A
        $string2 = /sudo\sapache2\s\-f\s\/etc\/shadow/ nocase ascii wide
        // Description: abusing LD_LIBRARY_PATH sudo option  to escalade privilege
        // Reference: N/A
        $string3 = /sudo\sLD_LIBRARY_PATH\=\.\sapache2/ nocase ascii wide
        // Description: abusinf LD_PREDLOAD option to escalade privilege
        // Reference: N/A
        $string4 = /sudo\sLD_PRELOAD\=\/tmp\/preload\.so\sfind/ nocase ascii wide

    condition:
        any of them
}