rule BeeLogger
{
    meta:
        description = "Detection patterns for the tool 'BeeLogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeeLogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Keylogger generator. fake office and acrobat file and malicious executables generator
        // Reference: https://github.com/4w4k3/BeeLogger
        $string1 = /Beelogger/ nocase ascii wide

    condition:
        any of them
}
