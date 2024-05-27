rule Omnispray
{
    meta:
        description = "Detection patterns for the tool 'Omnispray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Omnispray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string1 = /\sadfs\-spray\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string2 = /\sEASSniper\.ps1/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string3 = /\s\-\-module\so365_spray_activesync/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string4 = /\so365_enum_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string5 = /\so365_enum_office\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string6 = /\so365_enum_onedrive\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string7 = /\so365_spray_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string8 = /\so365_spray_adfs\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string9 = /\so365_spray_msol\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string10 = /\somnispray\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string11 = /\sowa_enum_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string12 = /\sowa_spray_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string13 = /\spaloalto_enum_globalprotectportal\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string14 = /\spaloalto_spray_globalprotectportal\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string15 = /\s\-\-type\senum\s\-uf\s.{0,1000}\s\-\-module\so365_enum_office/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string16 = /\s\-\-type\sspray\s\-uf\s.{0,1000}\s\-pf\s/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string17 = /\&passwd\=Winter2020\&ok\=Log\+In/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string18 = /\/adfs\-spray\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string19 = /\/dafthack\/MSOLSpray/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string20 = /\/EASSniper\.ps1/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string21 = /\/o365_enum_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string22 = /\/o365_enum_office\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string23 = /\/o365_enum_onedrive\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string24 = /\/o365_spray_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string25 = /\/o365_spray_adfs\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string26 = /\/o365_spray_msol\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string27 = /\/Omnispray\.git/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string28 = /\/omnispray\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string29 = /\/owa_enum_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string30 = /\/owa_spray_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string31 = /\/paloalto_enum_globalprotectportal\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string32 = /\/paloalto_spray_globalprotectportal\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string33 = /\[o365spray\]/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string34 = /\\adfs\-spray\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string35 = /\\dafthack\\MSOLSpray/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string36 = /\\EASSniper\.ps1/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string37 = /\\o365_enum_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string38 = /\\o365_enum_office\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string39 = /\\o365_enum_onedrive\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string40 = /\\o365_spray_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string41 = /\\o365_spray_adfs\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string42 = /\\o365_spray_msol\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string43 = /\\omnispray\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string44 = /\\Omnispray\-main/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string45 = /\\owa_enum_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string46 = /\\owa_spray_activesync\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string47 = /\\paloalto_enum_globalprotectportal\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string48 = /\\paloalto_spray_globalprotectportal\.py/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string49 = /0f638c5cbc07c8c0f3f2343f5459af22e80e6a4abaeef14740454486903fcbb8/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string50 = /0xZDH\/Omnispray/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string51 = /0xZDH\\Omnispray/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string52 = /130a517af6464f5a3d5e390b5fb90711029720b59cdeaab3c0300b4cf57227f9/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string53 = /2d0029543e5781ba1136a85707546c7b3acafbaa56cf71e917c63cc2f7fea794/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string54 = /3a1737f6fde0316cbc7552b8452384174908d9d124dd65016554a087455dd94e/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string55 = /4459ea3ad77b52ee723e8e8db6cf46ac565fefef5126717f7fc64d596cd4eb67/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string56 = /67d132f09b67e82cb54b941814c28737974165bcec5139909ed455fe97f2ab41/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string57 = /6cc5645274bdacebf9b7d37b49f7440184722f021e13c407df2f7fc71c2b8e5f/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string58 = /9e3a20cef67c034ac59b4793a8aa34cbdc7e130fe0ae791fe74059ba4ba0983d/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string59 = /a1b2d9ea6e99d95f0e69e4aed2008823f52a7bbea2e1e1a102e8ab2fcc370829/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string60 = /af190cf0778fc031a0db2eb2e36aaa0a09dea5495ce8a50d6e3eee439db3dc7a/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string61 = /b6be69e72453d7363a2570495b36897124c72b2676351307f9d0d1b2a90f1b9d/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string62 = /e336612e451075ecb75b27bd473aa21aba4f0a98df3cef57ad303894cce4f34b/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string63 = /e953e1f2e64f00273fe92e24d434d7a6619bb873d43bef5dd330d42de591dc8d/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string64 = /gist\.github\.com\/byt3bl33d3r\/19a48fff8fdc34cc1dd1f1d2807e1b7f/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string65 = /O365\sEnumeration\svia\sActiveSync\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string66 = /O365\sEnumeration\svia\sOffice\.com\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string67 = /O365\sEnumeration\svia\sOneDrive\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string68 = /O365\sSpraying\svia\sActiveSync\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string69 = /O365\sSpraying\svia\sADFS\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string70 = /O365\sSpraying\svia\sMSOL\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string71 = /Omnispray\s\|\sModular\sEnumeration\sand\sPassword\sSpraying\sFramework/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string72 = /OWA\sEnumeration\svia\sActiveSync\stiming\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string73 = /OWA\sSpraying\svia\sActiveSync\smodule\s\-\-/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string74 = /Password\sspraying\slockout\spolicy\sreset\stime\s/ nocase ascii wide
        // Description: Modular Enumeration and Password Spraying Framework
        // Reference: https://github.com/0xZDH/Omnispray
        $string75 = /Password\sspraying\sthe\sfollowing\spasswords\:\s/ nocase ascii wide

    condition:
        any of them
}
