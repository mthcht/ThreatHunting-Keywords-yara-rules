rule macro_pack
{
    meta:
        description = "Detection patterns for the tool 'macro_pack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "macro_pack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string1 = " --bypass --stealth --antisandox" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string2 = /\smacro_pack\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string3 = /\smimidropper\.hta/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string4 = /\smsfvenom\.bat/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string5 = /\/Base64ToBin\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string6 = /\/hta_gen\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string7 = /\/macro_pack\.exe/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string8 = /\/macro_pack\.git/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string9 = /\/macro_pack\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string10 = "/macro_pack/releases/download/" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string11 = /\/Meterpreter\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string12 = /\/meterpreter\.rc/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string13 = /\/mimidropper\.hta/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string14 = /\/msfvenom\.bat/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string15 = /\/obfuscate_strings\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string16 = /\/payload\.hta/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string17 = /\/uac_bypass\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string18 = /\/vba_gen\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string19 = /\[\+\]\sStarting\sMacro_Pack\sweb\sserver/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string20 = /\\Base64ToBin\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string21 = /\\empire_stager\.cmd/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string22 = /\\hta_gen\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string23 = /\\macro_pack\.exe/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string24 = /\\macro_pack\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string25 = /\\Meterpreter\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string26 = /\\meterpreter\.rc/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string27 = /\\mimidropper\.hta/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string28 = /\\msfvenom\.bat/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string29 = /\\obfuscate_strings\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string30 = /\\payload\.hta/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string31 = /\\uac_bypass\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string32 = /\\vba_gen\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string33 = /_processDropper2Template\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string34 = /_processDropperDllTemplate\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string35 = /_processDropperTemplate\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string36 = /_processEmbedDllTemplate\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string37 = /_processEmbedExeTemplate\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string38 = /_processMeterpreterTemplate\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string39 = /_processPowershellDropperTemplate\(/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string40 = "0365439c99fbf26126da61350ad8c424c6c0064c7cb3a9d2bc0b56674b01ed7c" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string41 = "049003aa4e196b115dd292dcb19a0308b45bfc160344a2f18edb537800b9d38e" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string42 = "05043d8400b0be454879f8d7f4c4455afa7ef1c9705176d1d95334f36e84bd53" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string43 = "07f1a35a2a86c46c5b0f70176aaacd6268b3dbf639d77bcf1b89235e8b44f327" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string44 = "205adce8325494081e929d923abc6585ae541546172483dc147b6ffe48b4f7f6" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string45 = "20b19292fa127311c14f893694a72b376d27b88c56ea2fb7b9fb816d9e0ab4d6" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string46 = "23bffbd2241b534574b8a9149c2502da4960f3a185437a9f983e51eebaf8ee1d" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string47 = "3ecabb1f5934079ee820bfe9f238ce6d780c2228563f55002a5921b1800118e1" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string48 = "4142dd9b827ddda740d7810e94f28d65a9aedeba637b8e3d785dba1947ccad52" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string49 = "524b9d99ab1bd72dd6b227ffc77c539c6abca8d429f56483dae709bc96e445dc" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string50 = "5be6fef49d21ddd81cfd1a8076c04385568d5120f20e0451bf4aaab0796e1656" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string51 = "61693b7ce852af0c5704294658176c64c547fc15401f7730261349340c47dba2" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string52 = "62f8b7689b4e41dd4035f0583ec04493d41f783e7d8152bb4dd4196e3bbc7cf5" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string53 = "6ef90637f19f9be257697a77dada7d97a1655705e821aa4b51eda2eed6e8751f" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string54 = "72eec1e82c566ff08110a4d06cd5b06cc82c67419131ad52fc537ff5552f69ab" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string55 = "80326cd79c767a6230f8b271ac764743b204d6c1af6cf7ac464ba5919f037e0d" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string56 = "96644c680528a212dff1c83615d8ca831fc21060c2dd08790bec98e6294576ee" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string57 = "967f010c2da33a4f2d610ec3bf7125430367e18d2f83baa18fa2b9172fd990ac" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string58 = "972963c83a5b6277233d9c33536b666a296b02137a267f685f7845e0b848d10b" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string59 = "99bedbdf28a0b90732b830ce18672ea3b5367b57bf0366714fefaa5d5e2d46f5" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string60 = "9c03a993cb73874e6e4ecbdd9c8df8b657f4f45395ae342e9206e56d72224d7c" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string61 = "9e9aaf77f76851a8d1da734637ed245260ad503de82fa4c886a070e29fdd3ee3" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string62 = "ac66758a6f95a4ec9aadef67b4bb85dec9aaa8fd98f0f52cbdfe519ac1c78d77" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string63 = "b394dc8dd4e30635b73da61c974d966752ed7712e6a4116b257baee6f7d1718f" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string64 = "b4c70e7499e46ab28c305ce9937933ea2674a16df3686830f6016c9321e23b84" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string65 = "bb8e4578feb7e957ef5b77433c1ee7cb339499d1bd05460848bc841871e0b672" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string66 = "c27a8cb8c4a97bbd0898799f3449d0f0a659360fc56cb43e0755bfeb25939241" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string67 = "C33A0993-A331-406C-83F5-9357DF239B30" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string68 = "c876220ab3ebb8d45afeb7dfc23ca6a0eff57a1e323533352c089768a6c487b6" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string69 = "ca245e03a26fd178305f09c391ee065899ab88dd3de6663b397a84d411f310fc" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string70 = "cmd /c ping localhost -n 1\"" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string71 = "d7792222dd6c580b5590d1cef292b118d7ebbab6570db74cb459ef9f3ee4c1f5" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string72 = "df1d68f681e71e7c78c734a467a4aa7d968c1bb11760868b13d93ffa7f65a0c0" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string73 = "e064a38f4cb8dbe91f3be32c1b2e925c40ceff78ce299bd1e6cf77339def978a" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string74 = "e6449478a32a49ac379f11e0f346267f44f590e777c32902e2bc06903118a69a" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string75 = "e6e7a49af780e80542a3b0e80b9bd524bcb513fa200800f7571112be8f681abb" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string76 = "ea4813fb19c07cb9d7c111c4808fa3eee05e3bf62694bc2481e50465c8853fda" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string77 = /emeric\.nasi\@sevagas\.com/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string78 = "f22360bb210b78e92b7aecfefb3c0c70e72e81cd03c1afd616e7691a744c3b28" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string79 = "f28955ff3d7997fbac71b4fe7c92a8b537566ace240455a312383792745c3e18" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string80 = "f7dc3c322ee7bb4d5f5b3ee99b8fefb47c6fccda3c112c4b2f4c36eae1a86247" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string81 = "fa9719d556cd1b8b951f7c1f561881c99da7cf41f25c41d8a87fab113144226a" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string82 = /http\:\/\/blog\.sevagas\.com\/\?Hacking\-around\-HTA\-files/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string83 = /http\:\/\/blog\.sevagas\.com\/\?My\-VBA\-Bot/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string84 = /https\:\/\/blog\.sevagas\.com\/\?Advanced\-MacroPack\-payloads\-XLM\-Injection/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string85 = /https\:\/\/blog\.sevagas\.com\/\?Bypass\-Windows\-Defender\-Attack\-Surface\-Reduction/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string86 = /https\:\/\/blog\.sevagas\.com\/\?EXCEL\-4\-0\-XLM\-macro\-in\-MacroPack\-Pro/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string87 = /https\:\/\/blog\.sevagas\.com\/\?Launch\-shellcodes\-and\-bypass\-Antivirus\-using\-MacroPack\-Pro\-VBA\-payloads/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string88 = /macro_pack\.exe\s\-G\s/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string89 = /mimikatz\.dll/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string90 = /modules\.obfuscate_strings/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string91 = /modules\.uac_bypass/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string92 = "msfvenom -p " nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string93 = "REM Generate meterpreter dll payload" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string94 = "sevagas/macro_pack" nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string95 = /UACBypassExecuteCMDAsync\.py/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string96 = /vbLib\.ExecuteCMDAsync/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string97 = /vbLib\.Meterpreter/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string98 = /vbLib\.UACBypassExecuteCMDAsync/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string99 = /vbLib\.WmiExec/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string100 = /vbLib\.WscriptExec/ nocase ascii wide
        // Description: The macro_pack is a tool used to automatize obfuscation and generation of retro formats such as MS Office documents or VBS like format. Now it also handles various shortcuts formats.
        // Reference: https://github.com/sevagas/macro_pack
        $string101 = /wmicexe\-whitelisting\-bypass\-hacking\.html/ nocase ascii wide

    condition:
        any of them
}
