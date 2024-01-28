rule Nsight_RMM
{
    meta:
        description = "Detection patterns for the tool 'Nsight RMM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Nsight RMM"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string1 = /\supload.{0,1000}\.systemmonitor\.eu\.com.{0,1000}\/command\/agentprocessor/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string2 = /\\Advanced\sMonitoring\sAgent\\debug\.log/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string3 = /\\Advanced\sMonitoring\sAgent\\staging/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string4 = /\\Advanced\sMonitoring\sAgent\\task_start\.js/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string5 = /\\Advanced\sMonitoring\sAgent\\unzip\.exe/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string6 = /\\Advanced\sMonitoring\sAgent\\winagent\.exe/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string7 = /\\Program\sFiles\s\(x86\)\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string8 = /\\Program\sFiles\\Advanced\sMonitoring\sAgent\\/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string9 = /\\Start\sMenu\\Programs\\Advanced\sMonitoring\sAgent\.lnk/ nocase ascii wide
        // Description: Nsight RMM usage
        // Reference: https://www.n-able.com/products/n-sight-rmm
        $string10 = /Advanced\sMonitoring\sAgent\sHTTP\sRetriever\s1\.1/ nocase ascii wide

    condition:
        any of them
}
