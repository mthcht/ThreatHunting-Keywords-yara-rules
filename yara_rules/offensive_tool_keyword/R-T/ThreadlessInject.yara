rule ThreadlessInject
{
    meta:
        description = "Detection patterns for the tool 'ThreadlessInject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ThreadlessInject"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string1 = /.{0,1000}\s\-p\s.{0,1000}\s\-d\s.{0,1000}\.dll\s\-e\sOpenProcess.{0,1000}/ nocase ascii wide
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string2 = /.{0,1000}\/ThreadlessInject\.git.{0,1000}/ nocase ascii wide
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string3 = /.{0,1000}CCob\/ThreadlessInject.{0,1000}/ nocase ascii wide
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string4 = /.{0,1000}Needles\swithout\sthe\sThread\.pptx.{0,1000}/ nocase ascii wide
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string5 = /.{0,1000}ThreadlessInject.{0,1000}\s\-p\s.{0,1000}\s\-d\s.{0,1000}/ nocase ascii wide
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string6 = /.{0,1000}ThreadlessInject\.exe.{0,1000}/ nocase ascii wide
        // Description: Threadless Process Injection using remote function hooking.
        // Reference: https://github.com/CCob/ThreadlessInject
        $string7 = /.{0,1000}ThreadlessInject\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
