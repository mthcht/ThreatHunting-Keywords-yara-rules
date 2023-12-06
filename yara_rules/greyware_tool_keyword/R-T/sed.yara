rule sed
{
    meta:
        description = "Detection patterns for the tool 'sed' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sed"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allowing root login for ssh
        // Reference: N/A
        $string1 = /sed\s\'s\/\#PermitRootLogin\sprohibit\-password\/PermitRootLogin\sYes\'\s\/etc\/ssh\/sshd_config/ nocase ascii wide

    condition:
        any of them
}
