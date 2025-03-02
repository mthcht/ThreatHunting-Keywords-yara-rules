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
        $string2 = /rm\s\.bash_history/
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string3 = "rm /var/log/"
        // Description: deleting log files
        // Reference: N/A
        $string4 = /rm\s\/var\/log\/.{0,1000}\.log/
        // Description: deleting bash history
        // Reference: N/A
        $string5 = /rm\s\~\/\.bash_history/
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string6 = /rm\s\-f\s.{0,1000}\.bash_history/ nocase ascii wide
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string7 = /rm\s\-f\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string8 = "rm -f /var/log/"
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string9 = /rm\s\-fr\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string10 = "rm -r /var/log/"
        // Description: Indicator Removal on Host
        // Reference: N/A
        $string11 = /rm\s\-rf\s.{0,1000}\.zsh_history/ nocase ascii wide
        // Description: delete bash history
        // Reference: N/A
        $string12 = /rm\s\-rf\s\.bash_history/
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string13 = "rm -rf /var/log/"
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string14 = "rm -rf /var/log/messages"
        // Description: Indicator Removal on Host - clearing logs
        // Reference: https://github.com/mthcht/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
        $string15 = "rm -rf /var/log/security"
        // Description: delete bash history
        // Reference: N/A
        $string16 = /rm\s\-rf\s\~\/\.bash_history/

    condition:
        any of them
}
