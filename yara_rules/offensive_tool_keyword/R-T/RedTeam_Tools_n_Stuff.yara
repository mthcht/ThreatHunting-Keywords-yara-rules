rule RedTeam_Tools_n_Stuff
{
    meta:
        description = "Detection patterns for the tool 'RedTeam_Tools_n_Stuff' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RedTeam_Tools_n_Stuff"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Schedules a file to be deleted on next Windows host reboot
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string1 = /\/DeleteonReboot\.exe/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string2 = /\/RedTeam_Tools_n_Stuff\.git/ nocase ascii wide
        // Description: minidumpwritedump a RtlCreateProcessReflection copy of a targeted Windows process
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string3 = /\/Vanity_Dump\.exe/ nocase ascii wide
        // Description: Schedules a file to be deleted on next Windows host reboot
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string4 = /\\DeleteonReboot\.exe/ nocase ascii wide
        // Description: minidumpwritedump a RtlCreateProcessReflection copy of a targeted Windows process
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string5 = /\\Vanity_Dump\.cpp/ nocase ascii wide
        // Description: minidumpwritedump a RtlCreateProcessReflection copy of a targeted Windows process
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string6 = /\\Vanity_Dump\.exe/ nocase ascii wide
        // Description: minidumpwritedump a RtlCreateProcessReflection copy of a targeted Windows process
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string7 = /\\Vanity_Dump\.sln/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string8 = /13ef95f2a3a43e67984999804e255ac93cdc9d9f8df85a188ba04700f6f4565c/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string9 = /17332F12\-D796\-42D1\-9A3E\-460590A49382/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string10 = /5782C660\-DD26\-40DC\-B06C\-B9275371EC55/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string11 = /63957210\-4871\-42D3\-B98A\-191AF5F91079/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string12 = /68ddd5703d6205313549d3828eeca64f383f297c43f65398f9a30637c07ef153/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string13 = /b305da79a7ce7057b89449f9113577f0e3e0a2a5ecc67299a806b56b65418856/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string14 = /C5C6F4EA\-7F09\-4AC7\-AC2A\-1246302B9856/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string15 = /E51B9AEB\-5F48\-4C5C\-837E\-3A2743917427/ nocase ascii wide
        // Description: Collection of self-made Red Team tools
        // Reference: https://github.com/samkenxstream/SAMkenXCCorePHdLAwiN8SoLr77
        $string16 = /RCStep\/RedTeam_Tools_n_Stuff/ nocase ascii wide

    condition:
        any of them
}
