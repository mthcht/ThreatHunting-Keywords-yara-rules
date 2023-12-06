rule SigPloit
{
    meta:
        description = "Detection patterns for the tool 'SigPloit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SigPloit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SigPloit a signaling security testing framework dedicated to Telecom Security professionals and reasearchers to pentest and exploit vulnerabilites in the signaling protocols used in mobile operators regardless of the geneartion being in use. SigPloit aims to cover all used protocols used in the operators interconnects SS7. GTP (3G). Diameter (4G) or even SIP for IMS and VoLTE infrastructures used in the access layer and SS7 message encapsulation into SIP-T. Recommendations for each vulnerability will be provided to guide the tester and the operator the steps that should be done to enhance their security posture
        // Reference: https://github.com/SigPloiter/SigPloit
        $string1 = /SigPloit/ nocase ascii wide

    condition:
        any of them
}
