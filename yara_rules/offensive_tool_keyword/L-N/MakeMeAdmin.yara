rule MakeMeAdmin
{
    meta:
        description = "Detection patterns for the tool 'MakeMeAdmin' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MakeMeAdmin"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string1 = /\/MakeMeAdmin\s.{0,1000}\sx64\.msi/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string2 = /\/MakeMeAdmin\.git/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string3 = /\/MakeMeAdmin\/tarball/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string4 = /\/MakeMeAdmin\/tree\/v.{0,1000}\/Installers/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string5 = /\/MakeMeAdmin\/zipball/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string6 = /\\MakeMeAdmin\s.{0,1000}\sx64\sDebug\.msi/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string7 = /\\MakeMeAdmin\s.{0,1000}\sx64\.msi/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string8 = /\\MakeMeAdmin\.sln/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string9 = /\\MakeMeAdmin\-main/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string10 = /\\SOFTWARE\\Policies\\Sinclair\sCommunity\sCollege\\Make\sMe\sAdmin/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string11 = /\\SOFTWARE\\Sinclair\sCommunity\sCollege\\Make\sMe\sAdmin/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string12 = /\>Enables\susers\sto\selevate\sthemselves\sto\sadministrator\-level\srights\.\</ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string13 = /\>Make\sMe\sAdmin\</ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string14 = /\>MakeMeAdmin\</ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string15 = /053c976a6b035d2c3daefe986d293fcb1d92ffd0f535a649ee61218c66721555/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string16 = /296176cf45851a6671437cced0cbfaf3aadf9c5d717ea973f911928a36a78442/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string17 = /37447f986ad651df8ea39416f5d5289fda6d3d48155e7ae257c086f9a2478de0/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string18 = /416656DC\-D499\-498B\-8ACF\-6502A13EFC9E/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string19 = /5FB1809B\-B0FD\-48E9\-9E47\-3CB048369433/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string20 = /63CAF2AD\-A016\-43BD\-AA27\-02CB848E2067/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string21 = /77612014\-2E37\-4E17\-AAFE\-9AD4F08B4263/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string22 = /79c64d376c00d7ccc3d946771a009fdcc9da4f066c9457805a19d1f804597466/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string23 = /8A516D69\-BA38\-429F\-AFFE\-C571B5C1E482/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string24 = /8dac9832\-d464\-4916\-b102\-9efa913bdc44/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string25 = /92C5208E\-DE76\-49F9\-B022\-1A558C95B6DF/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string26 = /9865ed1503bfac59d77f262ec4d443bc2eef2e850120ca601d406ff8d61c8bbb/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string27 = /9CFD5FA4\-5AD6\-463C\-87E5\-3F42133B5DA8/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string28 = /A2107C86\-7CB5\-45EE\-89E8\-1BC7261F7762/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string29 = /b5ad23ea9d77b64653171f466d8f325936a00bcc8917f6064c66ec146db8a3ba/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string30 = /B84EFDD8\-CEA0\-4CCA\-B7B8\-3F8AB3A336B4/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string31 = /baa689ba1163c0c06f50a93ffac5ed0e4494fef7f0091edb95fa1a76b1551a40/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string32 = /bc991b30cee4be589d540e1d0f055d62072843cbe1b95b27f40b860dc5aef935/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string33 = /bf05f1f8aa31c121f30b013e644b75f8ec16c23c6041140408c76d07b003738c/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string34 = /D64E40BB\-9DAC\-4491\-8406\-2CA2F2853F76/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string35 = /e15ab99b615fc244af70a7d6bd7e834f0851ca1da63c4f17043c80f931cc0d8a/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string36 = /e5a678fe7b074f6651954aa7c3643a21bf9019b9b0d504591a7c3e21283417ff/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string37 = /F5A53B43\-5D6D\-48EC\-BC44\-C0C1A0CEFA8D/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string38 = /makemeadmin\.com\// nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string39 = /MakeMeAdminRemoteUI\.exe/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string40 = /MakeMeAdminService\.exe/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string41 = /MakeMeAdminService\.fr/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string42 = /MakeMeAdminUI\.resources\.dll/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string43 = /net\.pipe\:\/\/.{0,1000}\/MakeMeAdmin\/Service\"/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string44 = /net\.tcp\:\/\/.{0,1000}\/MakeMeAdmin\/Service/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string45 = /pseymour\/MakeMeAdmin/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string46 = /ServiceBase\.Run\(new\sMakeMeAdminService\(/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string47 = /ServiceName\s\=\s\"MakeMeAdmin\"/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string48 = /SinclairCC\.MakeMeAdmin\.Properties/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string49 = /SinclairMakeMeAdmin\.adml/ nocase ascii wide
        // Description: Enables users to elevate themselves to administrator-level rights
        // Reference: https://github.com/pseymour/MakeMeAdmin
        $string50 = /SinclairMakeMeAdmin\.admx/ nocase ascii wide

    condition:
        any of them
}
