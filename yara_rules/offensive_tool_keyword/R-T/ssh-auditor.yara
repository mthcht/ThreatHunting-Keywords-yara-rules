rule ssh_auditor
{
    meta:
        description = "Detection patterns for the tool 'ssh-auditor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ssh-auditor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The best way to scan for weak ssh passwords on your network.
        // Reference: https://github.com/ncsa/ssh-auditor
        $string1 = /.{0,1000}ssh\-auditor.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
