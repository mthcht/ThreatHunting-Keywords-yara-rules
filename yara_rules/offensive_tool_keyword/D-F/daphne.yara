rule daphne
{
    meta:
        description = "Detection patterns for the tool 'daphne' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "daphne"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: evade auditd by tampering via ptrace
        // Reference: https://github.com/codewhitesec/daphne
        $string1 = /\/daphne\.git/ nocase ascii wide
        // Description: evade auditd by tampering via ptrace
        // Reference: https://github.com/codewhitesec/daphne
        $string2 = /\/daphne\-x64/ nocase ascii wide
        // Description: evade auditd by tampering via ptrace
        // Reference: https://github.com/codewhitesec/daphne
        $string3 = /codewhitesec\/daphne/ nocase ascii wide
        // Description: evade auditd by tampering via ptrace
        // Reference: https://github.com/codewhitesec/daphne
        $string4 = /daphne\-main\.zip/ nocase ascii wide
        // Description: evade auditd by tampering via ptrace
        // Reference: https://github.com/codewhitesec/daphne
        $string5 = /daphne\-x64\s.{0,1000}\spid\=/ nocase ascii wide

    condition:
        any of them
}
