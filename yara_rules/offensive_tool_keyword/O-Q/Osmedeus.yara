rule Osmedeus
{
    meta:
        description = "Detection patterns for the tool 'Osmedeus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Osmedeus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string1 = /.{0,1000}\/cloudbrute\.yaml.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string2 = /.{0,1000}\/osmedeus.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string3 = /.{0,1000}\/portscan\.yaml.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string4 = /.{0,1000}\/spider\.yaml.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string5 = /.{0,1000}\/subdomain\.yaml.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string6 = /.{0,1000}\/vulnscan\.yaml.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string7 = /.{0,1000}\/workflow\/test\/dirbscan\.yaml.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string8 = /.{0,1000}osmedeus\scloud.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string9 = /.{0,1000}osmedeus\shealth.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string10 = /.{0,1000}osmedeus\sprovider.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string11 = /.{0,1000}osmedeus\sscan.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string12 = /.{0,1000}osmedeus\sutils.{0,1000}/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string13 = /.{0,1000}scan\s\-T\slist_of_targets\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
