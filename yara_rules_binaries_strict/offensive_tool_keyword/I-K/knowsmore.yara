rule knowsmore
{
    meta:
        description = "Detection patterns for the tool 'knowsmore' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "knowsmore"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string1 = " --bloodhound --import-data " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string2 = " --bloodhound --mark-owned " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string3 = " --bloodhound --sync " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string4 = /\sbloodhoundsync\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string5 = /\sknowsmore\.cmd\.wordlist/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string6 = /\sknowsmore\.cmdbase/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string7 = /\sknowsmore\.config/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string8 = /\sknowsmore\.knowsmore/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string9 = /\sknowsmore\.libs\.bloodhoundsync/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string10 = /\sknowsmore\.libs\.exporterbase/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string11 = /\sknowsmore\.libs\.ntdsuseraccount/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string12 = /\sknowsmore\.module/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string13 = /\sknowsmore\.password/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string14 = /\sknowsmore\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string15 = /\sknowsmore\.util\.color/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string16 = /\sknowsmore\.util\.database/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string17 = /\sknowsmore\.util\.knowsmoredb/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string18 = /\sknowsmore\.util\.logger/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string19 = /\sknowsmore\.util\.process/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string20 = /\sknowsmore\.util\.tools/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string21 = /\sntdsuseraccount\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string22 = /\s\-\-ntlm\-hash\s\-\-company\s.{0,100}\s\-\-import\-cracked\s/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string23 = " --ntlm-hash --export-hashes " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string24 = /\s\-\-ntlm\-hash\s\-\-import\-ntds\s.{0,100}\.ntds/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string25 = " --secrets-dump -target " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string26 = /\ssecretsdump\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string27 = /\/bloodhoundsync\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string28 = /\/decrypting\-lsa\-secrets\.html/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string29 = /\/knowsmore\.cmd/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string30 = /\/knowsmore\.db/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string31 = /\/knowsmore\.git/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string32 = /\/knowsmore\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string33 = /\/ntdsuseraccount\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string34 = /\/secretsdump\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string35 = /\\bloodhoundsync\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string36 = /\\knowsmore\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string37 = /\\ntdsuseraccount\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string38 = /\\secretsdump\.py/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string39 = "087c26613e0a27bccb09de333278fb55c2b9cf3cf7600e36615353e67c1baaf9" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string40 = "0af6b417e2069876a8530e9ca0056ddc12b24f348e1d4a531add0760b8d11236" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string41 = "11ddcce3f411ffc78725cd4487998eb819324a19a502cd86852c9d8e2cc9659d" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string42 = "13d035ab6eb82b5527186ca674d8e17a018fd7389320d0df32c8fa2551df45d8" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string43 = "16a6b0fa183e54c07a78cdcea63df1d177aaafe8cf5737df9073e63fb03388a4" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string44 = "1af1c92c7a9a60a740d6351d935cb24d5c8ba7bde5a54bff8931a40bb6a2aa28" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string45 = "1aff544e58c3eda489ae9b59f32a10175d95e1aac12a4fbf25a40c40a1cc6c74" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string46 = "1e0d1441d6cc702501cd4fa67abc59887a1afedb25dc0b2aeda80cf168469883" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string47 = "2242362e7144103ecd965687227503de0483d4e7636218b1dd28cc01752bdb0f" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string48 = "23ef7c9571eb00b307253eafdd5821d52ccfa9a4a7225e328c450d9f6657be16" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string49 = "34b1b9b6a69e55a9a8ee08e26eb932ea6e8823c4a93c2d95e0e7b33376492827" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string50 = "387416cccea393e9e9eb2c069edabbf7297226037cc374d9a358ce1020696a5d" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string51 = "391d4825efd725d2deed4dd7d2addc62f38c3c8f15e84ada070aabc2303b4ab4" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string52 = "3b45f3db658c4628a97d2d8efa567415cb2e4cfc8a397570f0d33cc97c1aa78c" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string53 = "3c40fcf023afe126e8cc67593d21bc3ee9af7c56e3f1b8e9614cfd58030c29af" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string54 = "4243bea295573ba62e1bf4b685804539bab0286331a11e390f7e46abdc8ee785" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string55 = "46aee0547844dab640a8f982d4fb71207da42c0e00e214f2012680d3822adb85" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string56 = "553783ac96602dadd391b657eec078f7ab768c1b06bc04373e9fe9068f113041" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string57 = "5b095728389373e05a038fea724aa2dd66c3ff68b830cc651fd92177afe8c8b3" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string58 = "5e438cc32aa2a58190adc379d070d815afd1b03284eb7922b8daed40014ad1ef" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string59 = "61573b0cc19ea7bfb6ebe0ad6285d490710a1a09db5e32ab7e029ee466874bcc" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string60 = "6936c267e3cbb3bb7f418e26594bbf7367b7d2c8de6ad5d0e88c2cb3485dfcd9" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string61 = "6ed65758ecfa41680c567082d18526278b6e446b37046b578c6b1bf531d81f59" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string62 = "71e42659e0e9e225d76c33796093aaf32bc1f29359a6f8a4105b6e07c1c10df6" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string63 = "72d57c0c42ccd4ec3a220ac3c91cbb49b25cfcabebd30e36539980b52cfd49a4" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string64 = "7331b5c04c58757162a4448cc22df3483cbc4c38823a0e11026830f6cdfabf75" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string65 = "7d2dfbf053a420ad3857171642cbec5738196a0ead931f93737d16e14b7faec4" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string66 = "7da54ac68e35d2604980ef414a6ec8b696bf6ec5df2b32ad7596bee48db883c6" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string67 = "8a3bfd492f149d5c83675dd30e6ad94160534c980665609d6142f246552ac684" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string68 = "9e415352dda775398d02d9dd203367ce365c562da6227f72b77fb2916550345f" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string69 = "a6fe51ded3889aaf77c7b55814220c6e2ba19fac731f4387c472713d3b454dca" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string70 = "a78b41d1e1383a0aefbaba58881d1aa5b4a76457828ab5d60cb3b10ab075ca49" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string71 = "b350e1226b7d00487b47bec0f48320e85e3fb2546dc359cba3f2d77c75b5c599" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string72 = "BloodHound ZIP File identified, extracting" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string73 = "c1a30c8a226a6099fa0fc3d39e1fe4e83763ad52c41675b607ab569b7957f8a7" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string74 = "c7d3092d358e4828259d3b137eec1edeab112e2a70920c5912c76724e956ba47" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string75 = "c8808822c7f2fb60db3809d0700f739e39dca8c3d4918d01daa696ef8ed6a819" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string76 = "ca8e5157e4c093be717f36225fc1fb1fb4ffb1cf404cc9738c9a9fb7d41da29d" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string77 = "cb4490df575c59cc338804d8401be9782981fa7a5e9785a03781a3c135a8d837" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string78 = "cc81272307a9b746b67a9e9a52fbe5bc1f70f75c869480b517e16f34e20b80f5" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string79 = "cf0ef69e85418ec61f9200a26553738987c546710243bfae6c86b25edfdb5651" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string80 = "d83b72b8147d812d79c480142f74fa123115349052ab1d88df742c0cc8c1aca5" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string81 = "daa60ab697e9a8cd8ec70c7cc31de5692de1c878c425514788229e791c746e6b" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string82 = "Dumping cached domain logon information " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string83 = /Dumping\sDomain\sCredentials\s\(/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string84 = "e1ed880a56c4cbe995035969850bb409996edba8e31c05d654f525112026633f" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string85 = "e5285e73892bee5dd811a25cc0f2848fbe995c0aebfa2fd4ac533a8f2a619cec" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string86 = "e98bb5dcf6f202575e80431612a35d072adca1f57cb74d9e198dd51e6fe6a483" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string87 = "fbe35bdcceb19b3c20e8a212a5a6fa853e9d452321b75da7bbbb7666631c6dc4" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string88 = /from\s\.\simport\sknowsmore/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string89 = "from knowsmore import knowsmore" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string90 = "helviojunior/knowsmore" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string91 = "knowsmore --create-db" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string92 = "New password cracked! MTLM: " nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string93 = /NTDSHashes\.dump/ nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string94 = "pip install knowsmore" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string95 = "pip3 install --upgrade knowsmore" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string96 = "Policy SPN target name validation might be restricting full DRSUAPI dump" nocase ascii wide
        // Description: KnowsMore is a swiss army knife tool for pentesting Microsoft Active Directory (NTLM Hashes - BloodHound - NTDS and DCSync).
        // Reference: https://github.com/helviojunior/knowsmore
        $string97 = "vssadmin delete shadows /shadow=" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
