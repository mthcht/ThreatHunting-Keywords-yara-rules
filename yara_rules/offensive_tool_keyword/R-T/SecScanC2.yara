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
        $string1 = /.{0,1000}\/listProxyPool\?k\=.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string2 = /.{0,1000}\/SecScanC2\.git.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string3 = /.{0,1000}\/shell\?k\=.{0,1000}\&ip\=.{0,1000}\&cmd\=.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string4 = /.{0,1000}\/startProxyPool\?k\=.{0,1000}\&random\=n\&number\=2\&ip\=.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string5 = /.{0,1000}\/startProxyPool\?k\=.{0,1000}\&random\=y\&number\=2.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string6 = /.{0,1000}AE373FC4409EDA1B5F41D5CE3CA9290B3C7E8363.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string7 = /.{0,1000}SecScanC2_admin\s.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string8 = /.{0,1000}SecScanC2_admin_.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string9 = /.{0,1000}SecScanC2_node\s.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string10 = /.{0,1000}SecScanC2_node_.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string11 = /.{0,1000}SecScanC2\-main.{0,1000}/ nocase ascii wide
        // Description: SecScanC2 can manage assetment to create P2P network for security scanning & C2. The tool can assist security researchers in conducting penetration testing more efficiently - preventing scanning from being blocked - protecting themselves from being traced.
        // Reference: https://github.com/T1esh0u/SecScanC2
        $string12 = /.{0,1000}T1esh0u\/SecScanC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
