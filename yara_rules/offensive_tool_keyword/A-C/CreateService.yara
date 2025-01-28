rule CreateService
{
    meta:
        description = "Detection patterns for the tool 'CreateService' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CreateService"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string1 = /\\CreateService\-master\\/ nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string2 = /\\CreateService\-master\\CreateService\\/ nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string3 = /\]\sCreateService\sby\sUknow/ nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string4 = "1502b9bb17fe2a278c56ecfc1f3eb0cde62b083a260eda1ffe2423797962807d" nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string5 = "22020898-6F0D-4D71-B14D-CB5897C5A6AA" nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string6 = "2627fc45ff4accc08085a2e95ccaedf3ec4df6ddecb3339b747a4ca322e6d69b" nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string7 = "580ba177-cf9a-458c-a692-36dd6f23ea77" nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string8 = "9ccca75a916af75a20ae9ab06c2361cd2aa8ec8e2a0a741ebbbc762cbeb4d230" nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string9 = "cf25b9f3-849e-447f-a029-2fef5969eca3" nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string10 = /TransitPathName\sEvilPathName\sServiceName\sstart\/stop\\/ nocase ascii wide
        // Description: Creating a persistent service
        // Reference: https://github.com/uknowsec/CreateService
        $string11 = "uknowsec/CreateService" nocase ascii wide

    condition:
        any of them
}
