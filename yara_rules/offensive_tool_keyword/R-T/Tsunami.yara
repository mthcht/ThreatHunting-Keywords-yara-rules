rule Tsunami
{
    meta:
        description = "Detection patterns for the tool 'Tsunami' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tsunami"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\stsunami\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\stsunami_warning\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\"3R\<P4.{0,1000}\]7ye\+jT\=\,Y\%N3v\,hrWJ\^\%qH\?a\>5L\|q\[m\"/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\/ExecuteCommand_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\/FileBasic_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\/InternetConnect_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\/LoaderMemoryModule_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /\/LoadLibrary_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /\/SurveyFile_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /\/SurveyRegistry_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /\/TrustedWave_x64\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /\/tsunami\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /\/tsunami_warning\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = /\/TsunamiServer\// nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /\/TsunamiWave_x64\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = /\\ExecuteCommand_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string17 = /\\FileBasic_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string18 = /\\InternetConnect_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string19 = /\\LoaderMemoryModule_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string20 = /\\LoadLibrary_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string21 = /\\SurveyFile_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string22 = /\\SurveyRegistry_x64_Release\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string23 = /\\TrustedWave_x64\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string24 = /\\tsunami\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string25 = /\\tsunami_warning\.py/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string26 = /\\TsunamiServer\\agent\\/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string27 = /\\TsunamiWave_x64\.exe/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string28 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string29 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string30 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string31 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string32 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string33 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string34 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string35 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string36 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string37 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string38 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string39 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string40 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string41 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string42 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string43 = /042BF22B\-7728\-486B\-B8C9\-D5B91733C46D/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string44 = /191fdeb92ab3cf8ae11e804d907366ff7ee95d92f10b88f352aeeb3ea1d8ff52/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string45 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string46 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string47 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string48 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string49 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string50 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string51 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string52 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string53 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string54 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string55 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string56 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string57 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string58 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string59 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string60 = /5B5EF20C\-9289\-4E78\-A8AF\-2D30E44CF4F1/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string61 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string62 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string63 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string64 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string65 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string66 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string67 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string68 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string69 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string70 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string71 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string72 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string73 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string74 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string75 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string76 = /5D21B8F0\-3824\-4D15\-9911\-1E51F2416BC2/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string77 = /64\=\=eyJzbGVlcF9zZWNvbmRzIjogMjAsICJ2YXJpYXRpb25fc2Vjb25kcyI6IDB9/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string78 = /64\=\=eyJzbGVlcF9zZWNvbmRzIjogNSwgInZhcmlhdGlvbl9zZWNvbmRzIjogNn0\=/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string79 = /90DEB964\-F2FB\-4DB8\-9BCA\-7D5D10D3A0EB/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string80 = /97646f306c4b95f9733ee383923b7b8c954cd74715ff548ea42c8ae18fb2f67d/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string81 = /E3AEA3F6\-D548\-4989\-9A42\-80BAC9321AE0/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string82 = /ecec28a01376200b8746d6e2a9873d19b5191cdeb07ae926974b94d775b0c4cf/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string83 = /http\:\/\/192\.168\.126\.130\/upload\.php/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string84 = /Mozilla\/5\.0\s\(compatible\,\sMSIE\s11\,\sWindows\sNT\s6\.3\;\sTrident\/7\.0\;\srv\:11\.0\)\slike\sTsunamiWave/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string85 = /use\scommand\/file_basic_upload\.json/ nocase ascii wide
        // Description: another C2 framework
        // Reference: https://github.com/trustedsec/The_Shelf
        $string86 = /use\sinteractive\/command_prompt\.json/ nocase ascii wide

    condition:
        any of them
}
