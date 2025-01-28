rule chattr
{
    meta:
        description = "Detection patterns for the tool 'chattr' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chattr"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: lock out the ability to update the file
        // Reference: N/A
        $string1 = /chattr\s\+i\s\$HISTFILE/ nocase ascii wide
        // Description: lock out the ability to update the file
        // Reference: N/A
        $string2 = /chattr\s\+i\s.{0,1000}\.bash_history/
        // Description: changes the permissions and attributes of sensibles files
        // Reference: N/A
        $string3 = /chattr\s\-ia\s.{0,1000}\/etc\/passwd/
        // Description: changes the permissions and attributes of sensibles files
        // Reference: N/A
        $string4 = /chattr\s\-ia\s.{0,1000}\/etc\/shadow/
        // Description: changes the permissions and attributes of sensibles files
        // Reference: N/A
        $string5 = /chattr\s\-ia\s.{0,1000}\/etc\/sudoers/

    condition:
        any of them
}
