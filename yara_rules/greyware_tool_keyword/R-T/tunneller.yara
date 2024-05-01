rule tunneller
{
    meta:
        description = "Detection patterns for the tool 'tunneller' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunneller"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string1 = /\/tunneller\.git/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string2 = /\/tunneller\/releases\// nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string3 = /\/tunneller\-darwin\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string4 = /\/tunneller\-darwin\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string5 = /\/tunneller\-darwin\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string6 = /\/tunneller\-darwin\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string7 = /\/tunneller\-darwin\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string8 = /\/tunneller\-darwin\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string9 = /\/tunneller\-darwin\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string10 = /\/tunneller\-darwin\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string11 = /\/tunneller\-freebsd\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string12 = /\/tunneller\-freebsd\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string13 = /\/tunneller\-freebsd\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string14 = /\/tunneller\-freebsd\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string15 = /\/tunneller\-freebsd\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string16 = /\/tunneller\-freebsd\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string17 = /\/tunneller\-freebsd\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string18 = /\/tunneller\-freebsd\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string19 = /\/tunneller\-linux\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string20 = /\/tunneller\-linux\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string21 = /\/tunneller\-linux\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string22 = /\/tunneller\-linux\-amd64/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string23 = /\/tunneller\-linux\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string24 = /\/tunneller\-linux\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string25 = /\/tunneller\-linux\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string26 = /\/tunneller\-linux\-i386/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string27 = /087dae4b718907c400d19d3e497619042ad74036da714be2812ab423e0a86e84/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string28 = /1556d7d7fe7f2342854a24b05c3eca7e593d7e22021c559118c3fde32950bfd0/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string29 = /23588b81078e4ce796050b5eb3f87e37be16233d45ca17e222be509445127a3f/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string30 = /2d5d5cd63277002d698485c5a87a51c1c8d520a963ae1c1689c9e6c5c4964c0c/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string31 = /4f91e07aba2c4e94121f45cfb8252d2e173d565a4a15faacd7b3fa3f78b0d978/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string32 = /51921c04f725490abfce3611cef91f602314bb272240d7d4a252bf16a2199154/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string33 = /5370c48e778806b0676a70e133a32a7ed674ad22545bb61e120198236504245a/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string34 = /582b8f96d51ff83c2daf3970faa3c141a18dc8b1af0b23a3dc40aee1d04c6702/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string35 = /6c23f9dc5552c6286c852faa91236587470efaf28af92c5b4742feac70ffed6b/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string36 = /6f072e5783a999399690a8fbb7aff14f818746a910165bb7514576bf9ef179da/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string37 = /70bac6ab24591aa3df6592daacec697e11fdf865e3f27b8ccb7fa5a65934d96d/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string38 = /86f182e121994ab7f27c9936c947bf21151dbaa1a2c94640c9b3493e3101c98a/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string39 = /8bbfc29e4494eaa861f1e8ceea0982279cae939a7cbe4a6606919e07a67b85bc/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string40 = /959dfbb8cd213bd33aa99fcf4494c61397dc39685f43806ddd9804798d4c94cb/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string41 = /9f6b80fa0ffaad84c92776eaa2af7a16d5fcb724ac12ed9a07dffd88565c6397/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string42 = /a17972b286ec9492e224a2adcc4ec7487615caec87a04be7d7a1c0bbfc0f0b43/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string43 = /a857a9f7a34b247348439a6b13dda18e4aafa381eb7d50215610d9d360d68485/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string44 = /aca3bacd0f7f2a5e75ed74643e1fbb57ec10dc94f675dab12f8d7aeb48c3a503/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string45 = /ae4e32d838b180b920722598fa8cc91533742f1bc53805520b372f1f210d6833/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string46 = /b56153a4717acef3981496c1b7612efb801ce9b90ec941f1ebf69026d7fbbe20/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string47 = /b99def34d979c04dd81857a6ba93e79d8a16bcefecc8f4607e3c1cee097f41c1/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string48 = /c3a41b08c2665cc4036b9540ee39aa4a0786ed2416f03fe2ae5429ef303f409e/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string49 = /ce9e92734048598d84c3ca3a1da32ecdf759e43b3e13716bf0bf91183c7544f2/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string50 = /d49e100ae7518571c6b4953693cc63e975072203787c492f389326ea3b1e988f/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string51 = /eefd30efe33687408541ad00fead452f4f341c32fad1a77e84006ae7aa4fbe9a/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string52 = /efa4485dbd9d5813411e35144b17f676459fb681dc67c5a84d61da68f77099f8/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string53 = /Launch\sthe\sclient\,\sexposing\sa\slocal\sservice\sto\sthe\sinternet/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string54 = /skx\/tunneller/ nocase ascii wide
        // Description: Tunneller allows you to expose services which are running on localhost or on your local network to the public internet.
        // Reference: https://github.com/skx/tunneller
        $string55 = /You\smust\sspecify\sthe\slocal\shost\:port\sto\sexpose/ nocase ascii wide

    condition:
        any of them
}
