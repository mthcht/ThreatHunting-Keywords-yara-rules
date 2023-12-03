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
        $string1 = /.{0,1000}\s\-\-domains\s\.\/domains\.txt\srun.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string2 = /.{0,1000}\semailall\.py.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string3 = /.{0,1000}\/EmailAll\.git.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string4 = /.{0,1000}\/emailall\.py.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string5 = /.{0,1000}\\emailall\.py.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string6 = /.{0,1000}emailall\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string7 = /.{0,1000}emailall\.py\scheck.{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string8 = /.{0,1000}EmailAll\-master\..{0,1000}/ nocase ascii wide
        // Description: EmailAll is a powerful Email Collect tool
        // Reference: https://github.com/Taonn/EmailAll
        $string9 = /.{0,1000}Taonn\/EmailAll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
