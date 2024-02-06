rule rm
{
    meta:
        description = "Detection patterns for the tool 'rm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rm"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: deleting bash history
        // Reference: N/A
        $string1 = /rm\s\$HISTFILE/ nocase ascii wide
        // Description: deleting bash history
        // Reference: N/A
        $string2 = /rm\s\.bash_history/ nocase ascii wide
        // Description: deleting log files
        // Reference: N/A
        $string3 = /rm\s\/var\/log\/.{0,1000}\.log/ nocase ascii wide
        // Description: deleting bash history
        // Reference: N/A
        $string4 = /rm\s\~\/\.bash_history/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string5 = /rm\s\-rf\s\.bash_history/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string6 = /rm\s\-rf\s\~\/\.bash_history/ nocase ascii wide

    condition:
        any of them
}
