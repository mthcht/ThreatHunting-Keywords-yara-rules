rule wePWNise
{
    meta:
        description = "Detection patterns for the tool 'wePWNise' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wePWNise"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: wePWNise is proof-of-concept Python script which generates VBA code that can be used in Office macros or templates. It was designed with automation and integration in mind. targeting locked down environment scenarios. The tool enumerates Software Restriction Policies (SRPs) and EMET mitigations and dynamically identifies safe binaries to inject payloads into. wePWNise integrates with existing exploitation frameworks (e.g. Metasploit. Cobalt Strike) and it also accepts any custom payload in raw format.
        // Reference: https://github.com/FSecureLABS/wePWNise
        $string1 = /wePWNise/ nocase ascii wide

    condition:
        any of them
}
