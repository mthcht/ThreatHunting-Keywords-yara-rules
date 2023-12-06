rule EmailAll
{
    meta:
        description = "Detection patterns for the tool 'EmailAll' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EmailAll"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string1 = /\s\-\-domains\s\.\/domains\.txt\srun/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string2 = /\semailall\.py/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string3 = /\/EmailAll\.git/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string4 = /\/emailall\.py/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string5 = /\\emailall\.py/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string6 = /emailall\.py\s\-/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string7 = /emailall\.py\scheck/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string8 = /EmailAll\-master\./ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string9 = /Taonn\/EmailAll/ nocase ascii wide

    condition:
        any of them
}
