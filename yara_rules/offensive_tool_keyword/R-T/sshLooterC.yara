rule sshLooterC
{
    meta:
        description = "Detection patterns for the tool 'sshLooterC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sshLooterC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: script to steel password from ssh - Its the C version of sshLooter. which was written in python and have a lot of dependencies to be installed on the infected machine. Now with this C version. you compile it on your machine and send it to the infected machine without installing any dependencies.
        // Reference: https://github.com/mthbernardes/sshLooterC
        $string1 = /sshLooterC/ nocase ascii wide

    condition:
        any of them
}
