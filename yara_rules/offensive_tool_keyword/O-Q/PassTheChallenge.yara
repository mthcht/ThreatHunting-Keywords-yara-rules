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
        $string1 = /8F018213\-4136\-4D97\-9084\-F0346BBED04F/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string2 = /ly4k\/PassTheChallenge/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string3 = /PassTheChallenge\.cpp/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string4 = /PassTheChallenge\.exe/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string5 = /PassTheChallenge\.pdb/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string6 = /PassTheChallenge\.sln/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string7 = /PassTheChallenge\.vcxproj/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string8 = /PtC\.exe\schallenge/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string9 = /PtC\.exe\scompare/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string10 = /PtC\.exe\sinject/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string11 = /PtC\.exe\snthash\s/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string12 = /PtC\.exe\sping/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string13 = /PtC\.exe\sprotect/ nocase ascii wide

    condition:
        any of them
}
