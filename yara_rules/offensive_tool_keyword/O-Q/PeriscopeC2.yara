rule PeriscopeC2
{
    meta:
        description = "Detection patterns for the tool 'PeriscopeC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PeriscopeC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string1 = /\supload_c2profiles\.py/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string2 = /\/c2profiles\.zip/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string3 = /\/conf\/c2profiles\.json/
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string4 = /\/data\/assemblies\/SharpPick\.exe/
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string5 = /\/data\/assemblies\/SharpSendEmail\.exe/
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string6 = /\/data\/assemblies\/SharpView\.exe/
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string7 = "/data/dll/mimikatz/mimikatz"
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string8 = "/data/dll/PromptCreds/PromptCreds"
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string9 = /\/opt\/HttpRedirector\/conf\/periscope\.key/
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string10 = /\/opt\/periscope\/ControlCenter\/db\/periscope\.db/
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string11 = /\/raw\/master\/Release\/Happy\.exe/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string12 = /\/raw\/master\/Release\/Happy_x64\.exe/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string13 = /\/upload_c2profiles\.py/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string14 = /\\periscope_release_x64\.exe/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string15 = "5531A5C5-8710-48AD-BEFE-88E26F6CF798" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string16 = "6DE0DE7E-A81D-4194-B36A-3E67283FCABE" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string17 = "72DCE01A-B6EC-4AC3-A98B-D5C44D532626" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string18 = "ABF5940C-60AC-4892-B3F0-0F9262C550B3" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string19 = "AF7F4404-C746-43EC-86EA-8405473C95C9" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string20 = "api_username = \"\"redtiger1337\"\"" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string21 = /bdtryujndyund6e5\.azurewebsites\.net/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string22 = "CBAB0FE9-F4C0-49F2-90B1-7F34593F705A" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string23 = "D0DF8E42-3CED-4A5F-BB28-0C348B56BC79" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string24 = "EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string25 = "F5B94815-D623-4947-9A2B-88ABAF7FA6D9" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string26 = "http://localhost:4430/hello" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string27 = /mifunftyundf6deg\.azurewebsites\.net/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string28 = /mimikatz_x64\.dll/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string29 = /mimikatz_x86\.dll/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string30 = /nbdytundtyud5dey\.azurewebsites\.net/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string31 = /PeriscopeCLI\.SelectedHost\.HostData\.RegistryEntries/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string32 = /PromptCreds_x64\.dll/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string33 = /PromptCreds_x86\.dll/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string34 = "PwDLwAGAAkELwAGAK8ALwAOAE8FPgUGAG8FeQMGAK0ChwUOAC0FSAQOAMsASAQGABAFeQMAAAAAHAAAAAAAAQABAAAAEABxAxIDQQABAAEAUCAAAAAAkQA5ALQAAQDsIAAAAACRAOQD" nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string35 = /raheemabass55\@gmail\.com/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string36 = /ServiceName\s\=\s\\"\\"\[C2ProfileService\]/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string37 = /SG\.3xuRB22RTYaelD4sHiEBMw\.2wquktoAczDucX_KPgxXuo0xp\-h1hMnJ\-DLzBKOmIok/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string38 = /stager\/happy_x64\.txt/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string39 = /stager\/happy_x86\.txt/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string40 = /stager\/sad_x64\.txt/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string41 = /stager\/sad_x86\.txt/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string42 = /vpfxasdwnuewedfn\.azurewebsites\.net/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string43 = /WatermelonMakeup\.azurewebsites\.net/ nocase ascii wide
        // Description: walmart's C2 - complete adversarial operations toolkit (C2 - stagers - agents - automated ephemeral redirectors and task runners - a complete phishing engine)
        // Reference: https://github.com/malcomvetter/Periscope
        $string44 = /ytmrdnutyd5drtny\.azurewebsites\.net/ nocase ascii wide

    condition:
        any of them
}
