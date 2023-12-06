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
        $string1 = /\/cloudbrute\.yaml/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string2 = /\/osmedeus/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string3 = /\/portscan\.yaml/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string4 = /\/spider\.yaml/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string5 = /\/subdomain\.yaml/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string6 = /\/vulnscan\.yaml/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string7 = /\/workflow\/test\/dirbscan\.yaml/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string8 = /osmedeus\scloud/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string9 = /osmedeus\shealth/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string10 = /osmedeus\sprovider/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string11 = /osmedeus\sscan/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string12 = /osmedeus\sutils/ nocase ascii wide
        // Description: Osmedeus - A Workflow Engine for Offensive Security
        // Reference: https://github.com/j3ssie/osmedeus
        $string13 = /scan\s\-T\slist_of_targets\.txt/ nocase ascii wide

    condition:
        any of them
}
