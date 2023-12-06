rule NTLMRelay2Self
{
    meta:
        description = "Detection patterns for the tool 'NTLMRelay2Self' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTLMRelay2Self"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string1 = /\/NTLMRelay2Self/ nocase ascii wide
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string2 = /\\NTLMRelay2Self/ nocase ascii wide
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string3 = /inline\-execute\sStartWebClientSvc\.x64\.o/ nocase ascii wide
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string4 = /NTLMRelay2Self\.git/ nocase ascii wide

    condition:
        any of them
}
