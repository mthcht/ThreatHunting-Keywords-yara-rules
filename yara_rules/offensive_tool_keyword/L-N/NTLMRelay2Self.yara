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
        $string1 = /.{0,1000}\/NTLMRelay2Self.{0,1000}/ nocase ascii wide
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string2 = /.{0,1000}\\NTLMRelay2Self.{0,1000}/ nocase ascii wide
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string3 = /.{0,1000}inline\-execute\sStartWebClientSvc\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: An other No-Fix LPE - NTLMRelay2Self over HTTP (Webdav).
        // Reference: https://github.com/med0x2e/NTLMRelay2Self
        $string4 = /.{0,1000}NTLMRelay2Self\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
