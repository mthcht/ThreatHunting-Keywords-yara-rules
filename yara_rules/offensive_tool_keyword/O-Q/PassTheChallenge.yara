rule PassTheChallenge
{
    meta:
        description = "Detection patterns for the tool 'PassTheChallenge' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassTheChallenge"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string1 = /\/PassTheChallenge\.git/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string2 = /\/PassTheChallenge\/Constants\.h/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string3 = /\/PassTheChallenge\/Protocol_h\.h/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string4 = /\\PassTheChallenge\\PassTheChallenge\\/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string5 = /2116E6C5\-F609\-4CA8\-B1A1\-E87B7BE770A4/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string6 = /8F018213\-4136\-4D97\-9084\-F0346BBED04F/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string7 = /8F018213\-4136\-4D97\-9084\-F0346BBED04F/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string8 = /91302dd386709f514908c61d52d0e917ef6c4db866ee9f9f1b387ceb1e87cd7a/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string9 = /c4db3b4b49d8d75696f5641276d9ae1bcb990aaec46566719a7519810deb2f98/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string10 = /d4bc21da22b767a22840c442dd56536e0e5ab05932aa82899a43c29d49352932/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string11 = /ly4k\/PassTheChallenge/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string12 = /Pass\-the\-Challenge\s\(PtC\)\s\-\sby\sOliver\sLyak\s\(ly4k\)/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string13 = /PassTheChallenge\.cpp/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string14 = /PassTheChallenge\.exe/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string15 = /PassTheChallenge\.pdb/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string16 = /PassTheChallenge\.sln/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string17 = /PassTheChallenge\.vcxproj/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string18 = /PtC\.exe\schallenge/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string19 = /PtC\.exe\scompare/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string20 = /PtC\.exe\sinject/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string21 = /PtC\.exe\snthash\s/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string22 = /PtC\.exe\sping/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string23 = /PtC\.exe\sprotect/ nocase ascii wide

    condition:
        any of them
}
