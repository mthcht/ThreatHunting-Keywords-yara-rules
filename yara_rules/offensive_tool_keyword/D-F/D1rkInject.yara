rule D1rkInject
{
    meta:
        description = "Detection patterns for the tool 'D1rkInject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "D1rkInject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string1 = /\/D1rkInject\.git/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string2 = /\/MalStuff\.cpp/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string3 = /\\D1rkInject\\/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string4 = /\\MalStuff\.cpp/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string5 = /APT\sstands\sfor\sAdvanced\sPersistence\sTomato/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string6 = /BD602C80\-47ED\-4294\-B981\-0119D2200DB8/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string7 = /D1rkInject\.cpp/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string8 = /D1rkInject\.exe/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string9 = /D1rkInject\.iobj/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string10 = /D1rkInject\.log/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string11 = /D1rkInject\.sln/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string12 = /D1rkInject\.vcxproj/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string13 = /D1rkInject\-main/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string14 = /EEC35BCF\-E990\-4260\-828D\-2B4F9AC97269/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string15 = /TheD1rkMtr\/D1rkInject/ nocase ascii wide

    condition:
        any of them
}
