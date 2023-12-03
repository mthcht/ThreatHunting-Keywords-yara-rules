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
        $string1 = /.{0,1000}8F018213\-4136\-4D97\-9084\-F0346BBED04F.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string2 = /.{0,1000}ly4k\/PassTheChallenge.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string3 = /.{0,1000}PassTheChallenge\.cpp.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string4 = /.{0,1000}PassTheChallenge\.exe.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string5 = /.{0,1000}PassTheChallenge\.pdb.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string6 = /.{0,1000}PassTheChallenge\.sln.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string7 = /.{0,1000}PassTheChallenge\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string8 = /.{0,1000}PtC\.exe\schallenge.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string9 = /.{0,1000}PtC\.exe\scompare.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string10 = /.{0,1000}PtC\.exe\sinject.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string11 = /.{0,1000}PtC\.exe\snthash\s.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string12 = /.{0,1000}PtC\.exe\sping.{0,1000}/ nocase ascii wide
        // Description: Recovering NTLM hashes from Credential Guard
        // Reference: https://github.com/ly4k/PassTheChallenge
        $string13 = /.{0,1000}PtC\.exe\sprotect.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
