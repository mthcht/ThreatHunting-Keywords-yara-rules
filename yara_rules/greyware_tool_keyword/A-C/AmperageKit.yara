rule AmperageKit
{
    meta:
        description = "Detection patterns for the tool 'AmperageKit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AmperageKit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string1 = /\/Amperage\.exe/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string2 = /\/AmperageKit\.git/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string3 = /\/AmperageKit\/releases\// nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string4 = /\\Amperage\.exe/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string5 = /\\Amperage\\Program\.cs/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string6 = /\\Amperage_v2024\.5\.31_arm64\.zip/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string7 = /\\Amperage_v2024\.6\.1_arm64\.zip/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string8 = /\\AmperageAIXSysRemove/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string9 = /\\AmperageHwReqDetour/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string10 = /\\AmperageKit\.sln/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string11 = /\\ProgramData\\Amperage/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string12 = /327F3F26\-182F\-4E58\-ABEA\-A0CEDBCA0FCD/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string13 = /3bdf7c5f0c87c94b461668137a3e7cbf757d59dafc7a063362c34d17f2f33e61/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string14 = /7334543f2f3555690c9a4995cf1d8e83beb9fa45e6aa147c49114a4ef89670b8/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string15 = /75dce532b65a7c7644a626196a8af9d8370e163e802847505fb033a6290fb4a5/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string16 = /7931404e96b6aff52bc81a852f1f545f0cd07712d648099ec0618f4e66a1807f/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string17 = /80C7245C\-B926\-4CEB\-BA5B\-5353736137A8/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string18 = /8e454334de0de74a6e53ee1d26e24cd2b0f41427922d9e92e6d49cf5db942a3c/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string19 = /A3454AF1\-12AF\-4952\-B26D\-FF0930DB779E/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string20 = /Amperage\s\-\sRecall\ssetup\stool\sfor\sunsupported\shardware/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string21 = /cd1c54a8510c1e09d55868e12872aa54f9dc9ade95d70f08a173d29f6d676fde/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string22 = /d84efd06178700a83d135862d6c7419dce2e12df92c78850dc7cc5b1da482abd/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string23 = /ed0375afd9b26b18fd9b72bbb416dbf8bec289bf135facf4b7ba5cd2b1d86208/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string24 = /Removing\sAIX\spackage\sfrom\sall\sstandard\susers/ nocase ascii wide
        // Description: enabling Recall in Windows 11 version 24H2 on unsupported devices
        // Reference: https://github.com/thebookisclosed/AmperageKit
        $string25 = /thebookisclosed\/AmperageKit/ nocase ascii wide

    condition:
        any of them
}
