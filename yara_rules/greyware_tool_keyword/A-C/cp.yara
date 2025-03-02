rule cp
{
    meta:
        description = "Detection patterns for the tool 'cp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: copies the Bash binary to the /tmp/ directory
        // Reference: N/A
        $string1 = "cp /bin/bash /tmp/"
        // Description: copies the Bash binary to the /tmp/ directory
        // Reference: N/A
        $string2 = "cp /bin/sh /tmp/"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string3 = "cp /etc/passwd"
        // Description: linux commands abused by attackers - find guid and suid sensitives perm
        // Reference: N/A
        $string4 = "cp /etc/shadow"
        // Description: copies the Bash binary to the /tmp/ directory
        // Reference: N/A
        $string5 = "cp -i /bin/bash /tmp/"
        // Description: copies the Bash binary to the /tmp/ directory
        // Reference: N/A
        $string6 = "cp -i /bin/sh /tmp/"

    condition:
        any of them
}
