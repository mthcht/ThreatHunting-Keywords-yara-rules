rule AV_Evasion_Tool
{
    meta:
        description = "Detection patterns for the tool 'AV_Evasion_Tool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AV_Evasion_Tool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string1 = /\/AV_Evasion_Tool\.git/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string2 = /\\\\Windows\\\\Temp\\\\Yanri_res\.rc/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string3 = /\\Temp\\YANRI_TEMP_/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string4 = /03963c5f7fbaf997cc971aa4a2367f68eb694f3cc35fe9408e423f1919c356a1/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string5 = /03e553f277ccbe4916eefcd15c17178c7690c64d8533073c86c4a60481649239/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string6 = /1958310b6f2ab97181768cdebab34fd9eff9218280b9a6a753800009ded8f9b7/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string7 = /1y0n\/AV_Evasion_Tool/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string8 = /2bedfede524b3c27ab02fcdc3fd4b7e54c1aa83cad0e7642ff4c70700f51355a/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string9 = /2d3968ad60bdbc9528f95568aba38693ade0090f8d57707dc3e288d792587a35/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string10 = /2ff605e64eb4fa723b59b90f9ef36c5aeb4332695367697e91997a5b6dc463ba/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string11 = /309a7793f785eec671771cbf3bdb33f17cfd71702d0bfc482f6780c8aaa66876/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string12 = /3a5252edbc3926fde111e30235830dd0cbcb8f89efab7c24864db2a5399a5c3c/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string13 = /3fbcc1db198e03bc5d6087c69e311fd97fe9861a7721526e9ea1d44e2398d022/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string14 = /425f2ddd85773aaf592043762f9132ef2173ef8ec2e69ce2d049d329dd9685b2/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string15 = /45ff440d387c984f8bd7be1d1bc77cd9eaf70aa513a2a4c80189294a0f70c411/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string16 = /46ba6286810d79be37facbd8c315a35acc1d49dc012870a50014eaff1bcd1fbd/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string17 = /4b7f6f3571fda33d3c305207518d9a7a8f328e2828f249735368beb8b6f04210/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string18 = /4e352b020c8f888cb620a64282df6b60a862f905e831101d060a0fbdbbb25932/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string19 = /4ef27da3276651f20e1d401412bb95c823f277b7a28f693eed55f819aa65e7bf/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string20 = /59f031b1f9b71d2166f1b281b3ffbe40e3985d3a739d1761e59434a0032bf5c6/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string21 = /5ea4f3837040a1342e8eed81e10d5dcf1e28f1b67478d8cd421007201758995f/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string22 = /65f5366b645bcc846eb270d514fd8f1c777a3a7b7534a6364e251268e9741346/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string23 = /6a9a3b838e5547654d9b0d9024e2afcaa0ad721de33499d192684cda337d49f5/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string24 = /723dfeeb1318c43343f21b49f3ae06a9b3d5e2d4ae5dda61fb57bee39a7b30da/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string25 = /7898617D\-08D2\-4297\-ADFE\-5EDD5C1B828B/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string26 = /7fdb39ce9dcd83556dccda4a7480917b87ddef21edc96db5f0a1d134c40453cd/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string27 = /8819246132617282fade672cf544bff340d1a286980bce9c59b9ae41e221fc8f/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string28 = /8a22596f3783d65822de3eee7a72899699d1fffb885404ddf9c1cb0b8b780442/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string29 = /8db6879b0c3f33cf027515fb91fa397a09f2989ef9660b3243901ae38f6ace3c/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string30 = /93d0d9ef1c1e2828b282ece1f3ce06624f1a27fca3d4a78e36fcaf672cf9c5b5/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string31 = /9cd7f22a7d202899c075a524124a9509bc5dffd09ff2e797074e074a1ad48a5c/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string32 = /9da47a94bbb8d9322de8b7bb34958578776a47fdd440d2cca413fec7c78bc795/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string33 = /a425fc824f3bf40f82faad797a69b0fc2556dc79579f566891e75ee00920f7c0/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string34 = /a6fa0c8acd7fae1a71d6f623caf345eb427b40db045c081f394b0e67e9bc14a5/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string35 = /ab85375c8fcfcea1cf4135cc834b762c1006903496d70b795d4eb34cc6f754ec/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string36 = /Advanced\.AV\.Evasion\.Tool\.For\.Red\.Team\.exe/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string37 = /b262b397386f413b6b815b409d54a9c5ae65dc0730c3d9918132a23f3d99a1da/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string38 = /b37aa3dcdebe406d652a4cfc3fb54168ea6525787fca00876452823f8b33605e/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string39 = /b49abe3651b2e07c875f149d9931820ca27237d929814c94b2cfa32f1a445737/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string40 = /b504d1a33068b6bde4059071fd7c89d8f9535185f6aad0d1e1361259f66fb529/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string41 = /b83dc319987bebf9dca8b6e85671f9bdced13236275598a29e8669842a225bbb/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string42 = /b988905cfe09a6fb9a8f034a2efb0403731b2eeb29e19403d3eaade2b02fdfbd/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string43 = /ba7e216ca801f1b05c2cc100226b5d8f90263ee92f910a6febf637bb7ae3bec7/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string44 = /bb62708fb9f961bffe55ec0fd74eead24e9d0b6c9e1ef054c845e7bc23af70a8/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string45 = /c00ed94009fe6719c5c7803fe7d96a4930693897bc8335cb2c11d749052ffbdb/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string46 = /c14cdcc5244fa9bb63ef50f28b2699c3cac0d42bd983ddb823a635842d0b143a/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string47 = /c332926e2e1de5a7c696feebfd5996c8b78ef9a380a9e4a8da85a3485f0f3288/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string48 = /c6323bd50315806228e24f7521ad096683beb5483bffb3eca4bbeb4f5a81d3f3/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string49 = /c728e54e57a93ffbbe606d72fa12abb736236e7a1e263b49cf7e302de32f1100/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string50 = /d79d4da3258689d4510878b28b66c5bc15542107d6a25a6c2a55099a31762a22/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string51 = /d92e344caa4b6b913bad4f77a2bd6e771434a95a4fd2c8cea0fec75edba58568/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string52 = /d97e7cfd07d94c8282968f0334349056364f4e040a649f43577b9992204e2790/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string53 = /e080a9a96cea5b322687be0113ce158715ba988532e3800d37a8690767c0d22e/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string54 = /e2fef0ec8523ec22594297061e813d69f48f47e33d99f2f96f63a0abc053aa51/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string55 = /e409901ebcba3869ad50844d6896bc466ef54546ceb06bd5949d9f667ade3e06/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string56 = /e7fc34563fba238982ec178b82d38c2a182f3d5409a291a5a0ada363d5b292b0/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string57 = /eaa667b2ee62c5960b2a1ae23ec8edbdb89de0897960cf9f5117b721f519ae98/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string58 = /eaf85e2ba4dd79f5ef5d8d18c5886dc8cde0e18e7341e6808baf3d9a5bafed7d/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string59 = /f1c61181201c45d01a05a4c00d6e2f392e4afcf7c4133f71151ef6ad20887d17/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string60 = /f67a93fa0870a0ef178d165eb20fb77d60c1a87e5b82851c63aad115ffe90bd4/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string61 = /f752cf3610b17c90e8a4b03ffd0dc9de1f2005108556708108f940e78d57bde6/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string62 = /f8fb6472ba4d0cd5bd54881ee9a69a9d5fec9f5b6e40ec1b3850208eb045db56/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string63 = /fa66e3077a51a5ef7cb29ab869b483d7363e9bb58d84595de4e0b2b48e3df47b/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string64 = /fc9db4d8355ff19b09feb69b73f4c551a1e11158abaf795b16081b24f56b321a/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string65 = /o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA\+SItyUD5ID7dK/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string66 = /pwd\+c5eeCXJF7Mxr3qeKtaTa2727SSpvYnGD2ptzGMnNO0iye/ nocase ascii wide
        // Description: Undetectable Payload Generator Tool
        // Reference: https://github.com/1y0n/AV_Evasion_Tool
        $string67 = /PwDxOWaXzpP3j\/eP8RpnnSf89H\/76NEv\+uk\/3j\/OmYrqMLj\/ADpf/ nocase ascii wide

    condition:
        any of them
}
