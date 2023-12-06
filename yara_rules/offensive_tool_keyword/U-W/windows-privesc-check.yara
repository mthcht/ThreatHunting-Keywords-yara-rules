rule windows_privesc_check
{
    meta:
        description = "Detection patterns for the tool 'windows-privesc-check' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-privesc-check"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: privesc script checker - Windows-privesc-check is standalone executable that runs on Windows systems. It tries to find misconfigurations that could allow local unprivileged users to escalate privileges to other users or to access local apps (e.g. databases).
        // Reference: https://github.com/pentestmonkey/windows-privesc-check
        $string1 = /privesc\-check/ nocase ascii wide

    condition:
        any of them
}
