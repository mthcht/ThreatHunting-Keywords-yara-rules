rule SecScanC2
{
    meta:
        description = "Detection patterns for the tool 'SecScanC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SecScanC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string1 = /\/listProxyPool\?k\=/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string2 = /\/SecScanC2\.git/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string3 = /\/shell\?k\=.{0,1000}\&ip\=.{0,1000}\&cmd\=/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string4 = /\/startProxyPool\?k\=.{0,1000}\&random\=n\&number\=2\&ip\=/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string5 = /\/startProxyPool\?k\=.{0,1000}\&random\=y\&number\=2/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string6 = /AE373FC4409EDA1B5F41D5CE3CA9290B3C7E8363/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string7 = /SecScanC2_admin\s/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string8 = /SecScanC2_admin_/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string9 = /SecScanC2_node\s/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string10 = /SecScanC2_node_/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string11 = /SecScanC2\-main/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string12 = /T1esh0u\/SecScanC2/ nocase ascii wide

    condition:
        any of them
}
