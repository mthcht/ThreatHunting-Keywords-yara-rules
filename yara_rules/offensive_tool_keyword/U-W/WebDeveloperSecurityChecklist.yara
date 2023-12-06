rule WebDeveloperSecurityChecklist
{
    meta:
        description = "Detection patterns for the tool 'WebDeveloperSecurityChecklist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WebDeveloperSecurityChecklist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A checklist of important security issues you should consider when creating a web application.can be used by attacker to check wweakness to exploit
        // Reference: https://github.com/virajkulkarni14/WebDeveloperSecurityChecklist
        $string1 = /WebDeveloperSecurityChecklist/ nocase ascii wide

    condition:
        any of them
}
