rule PSAttack
{
    meta:
        description = "Detection patterns for the tool 'PSAttack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PSAttack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PS>Attack combines some of the best projects in the infosec powershell community into a self contained custom PowerShell console. Its designed to make it easy to use PowerShell offensively and to evade antivirus and Incident Response teams. It does this with in a couple of ways.
        // Reference: https://github.com/jaredhaight/PSAttack
        $string1 = /PSAttack/ nocase ascii wide

    condition:
        any of them
}