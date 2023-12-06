rule wmiexec2
{
    meta:
        description = "Detection patterns for the tool 'wmiexec2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wmiexec2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: wmiexec2.0 is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string1 = /\/remoteshell\.py/ nocase ascii wide
        // Description: wmiexec2.0 is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string2 = /\/wmiexec2\.git/ nocase ascii wide
        // Description: wmiexec2.0 is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string3 = /ice\-wzl\/wmiexec2/ nocase ascii wide
        // Description: wmiexec2.0 is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string4 = /wmiexec2\.0\.py/ nocase ascii wide
        // Description: wmiexec2.0 is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string5 = /wmiexec2\.py/ nocase ascii wide
        // Description: wmiexec2.0 is the same wmiexec that everyone knows and loves (debatable). This 2.0 version is obfuscated to avoid well known signatures from various AV engines.
        // Reference: https://github.com/ice-wzl/wmiexec2
        $string6 = /wmiexec2\-main/ nocase ascii wide

    condition:
        any of them
}
