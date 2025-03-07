rule linuxprivchecker
{
    meta:
        description = "Detection patterns for the tool 'linuxprivchecker' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "linuxprivchecker"
        rule_category = "signature_keyword"

    strings:
        // Description: search for common privilege escalation vectors such as world writable files. misconfigurations. clear-text passwords and applicable exploits
        // Reference: https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py
        $string1 = /HackTool\:Python\/Empire\.C\!MTB/

    condition:
        any of them
}
