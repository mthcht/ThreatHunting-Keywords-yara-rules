rule go_lsass
{
    meta:
        description = "Detection patterns for the tool 'go-lsass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "go-lsass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string1 = /\/go\-lsass\.exe/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string2 = /\/go\-lsass\.git/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string3 = "/go-lsass/releases" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string4 = /\/go\-lsass\-master\.zip/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string5 = /\\go\-lsass\.exe/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string6 = /\\go\-lsass\-master\.zip/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string7 = /\\go\-lsass\-master\\/ nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string8 = "16386980a156fc6e9219ba230c5fd2759e4b43dff9261487598e7d0ecfe78ae0" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string9 = "455a614b6dd52b17b4af639045bd0c3c3ddad152334607978ec9e915553246e9" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string10 = "a7e8aade00d2cd5aeb6ec40d5b64f6cac88f120efb4efb719567e758af5892c2" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string11 = "db5a054172dcde3aebfb86b08e3bf8992f9df3d22e2028fd5154c647e7361ceb" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string12 = "go-lsass --host "
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string13 = "jfjallid/go-lsass" nocase ascii wide
        // Description: dumping LSASS process remotely
        // Reference: https://github.com/jfjallid/go-lsass
        $string14 = "Successfully downloaded the LSASS dump into local file" nocase ascii wide

    condition:
        any of them
}
