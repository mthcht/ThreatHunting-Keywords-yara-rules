rule ssh_mitm
{
    meta:
        description = "Detection patterns for the tool 'ssh-mitm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh-mitm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An SSH/SFTP man-in-the-middle tool that logs interactive sessions and passwords.
        // Reference: https://github.com/jtesta/ssh-mitm
        $string1 = /ssh\-mitm/ nocase ascii wide

    condition:
        any of them
}
