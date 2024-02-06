rule tmpwatch
{
    meta:
        description = "Detection patterns for the tool 'tmpwatch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpwatch"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string1 = /chmod\s4777\s\/tmp\/\.scsi\/dev\/bin\/gsh/ nocase ascii wide
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string2 = /chown\sroot\:root\s\/tmp\/\.scsi\/dev\/bin\// nocase ascii wide
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string3 = /echo\s.{0,1000}bailing\.\stry\sa\sdifferent\sname\\/ nocase ascii wide
        // Description: Equation Group hack tool set command exploitation- tmpwatch - removes files which haven't been accessed for a period of time
        // Reference: https://linux.die.net/man/8/tmpwatch
        $string4 = /if\s\[\s\-f\s\/tmp\/tmpwatch\s\]\s.{0,1000}\sthen/ nocase ascii wide

    condition:
        any of them
}
