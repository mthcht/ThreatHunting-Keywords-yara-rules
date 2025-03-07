rule rundll32
{
    meta:
        description = "Detection patterns for the tool 'rundll32' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rundll32"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Caling MiniDump function - dump memory of a process (often abused to dump lsass process)
        // Reference: N/A
        $string1 = /comsvcs\.dll\,\sMiniDump\s/ nocase ascii wide
        // Description: Calling MiniDump export by ordinal - dump memory of a process (often abused to dump lsass process
        // Reference: N/A
        $string2 = /comsvcs\.dll\,\#24\s/ nocase ascii wide
        // Description: dumping lsass
        // Reference: N/A
        $string3 = /lsass.{0,1000}rundll32\.exe\s.{0,1000}comsvcs\.dll\,\sMiniDump\s.{0,1000}\.dmp\sfull/ nocase ascii wide
        // Description: Detects the use of getsystem Meterpreter/Cobalt Strike command. Getsystem is used to elevate privilege to SYSTEM account.
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string4 = /rundll32.{0,1000}\.dll.{0,1000}a.{0,1000}\/p\:/ nocase ascii wide
        // Description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
        // Reference: https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence
        $string5 = /rundll32.{0,1000}\.dll.{0,1000}StartW/ nocase ascii wide
        // Description: Caling MiniDump function - dump memory of a process (often abused to dump lsass process)
        // Reference: N/A
        $string6 = /rundll32.{0,1000}comsvcs\.dll\sMiniDump\s/ nocase ascii wide
        // Description: dumping lsass
        // Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/win_meterpreter_or_cobaltstrike_getsystem_service_start.yml
        $string7 = /rundll32\.exe\s.{0,1000}comsvcs\.dll\,\sMiniDump\s.{0,1000}lsass.{0,1000}full/ nocase ascii wide

    condition:
        any of them
}
