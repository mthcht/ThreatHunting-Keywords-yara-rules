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
        $string1 = /.{0,1000}\/D1rkInject\.git.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string2 = /.{0,1000}\/MalStuff\.cpp.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string3 = /.{0,1000}\\D1rkInject\\.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string4 = /.{0,1000}\\MalStuff\.cpp.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string5 = /.{0,1000}APT\sstands\sfor\sAdvanced\sPersistence\sTomato.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string6 = /.{0,1000}BD602C80\-47ED\-4294\-B981\-0119D2200DB8.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string7 = /.{0,1000}D1rkInject\.cpp.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string8 = /.{0,1000}D1rkInject\.exe.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string9 = /.{0,1000}D1rkInject\.iobj.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string10 = /.{0,1000}D1rkInject\.log.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string11 = /.{0,1000}D1rkInject\.sln.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string12 = /.{0,1000}D1rkInject\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string13 = /.{0,1000}D1rkInject\-main.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string14 = /.{0,1000}EEC35BCF\-E990\-4260\-828D\-2B4F9AC97269.{0,1000}/ nocase ascii wide
        // Description: Threadless injection that loads a module into the target process and stomps it and reverting back memory protections and original memory state
        // Reference: https://github.com/TheD1rkMtr/D1rkInject
        $string15 = /.{0,1000}TheD1rkMtr\/D1rkInject.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
