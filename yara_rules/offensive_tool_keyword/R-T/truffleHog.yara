rule truffleHog
{
    meta:
        description = "Detection patterns for the tool 'truffleHog' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "truffleHog"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string1 = " install trufflehog"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string2 = /\/trufflehog\.git/
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string3 = "/trufflehog/releases/download/"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string4 = "/trufflehog:latest "
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string5 = "022f86896e1a525969c4f067a241fce1e6435084d5cef6bc048adfdedc9df1de"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string6 = "04e6af8c093849416d46aa2d45c30bdf3501676621c43d15e7200f219c580c55"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string7 = "07e05292767dac077c0314535d073a90f742f25456880b2bf5311c4cf8169b91"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string8 = "0b2cf2f9b7ff24e97c75b4791a431011d1e58824491a1e4b63ff6eeae13282cb"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string9 = "0c35e11198ce91ce473f38aa0d3d4ac7a6c7e1c50ef229f5f6019ad95846ea4c"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string10 = "1610107593861f211a6dc6e886cd8a4ec67bef2ede1072195746462ecb79babd"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string11 = "21af546e3eedebde001b961737c7c3d152d145baf1784c62690211c568a17da7"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string12 = "259322fe4426ae2d44fd68942705f889a5f292aecdb164d4b92302c0eedd3f28"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string13 = "3010a92d74293dc8e410f48f329b221230818b206f57fda830acb449bd53497d"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string14 = "35d2dc2cf8f535667b487b012b1d0efad5ceca399967923a580f1929f5717c52"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string15 = "3da6057398b0a35098b4c4d944bf3df03eda0a05b6383d230e32b49733561a86"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string16 = "537ea05a68fa2fc81101b89b2a603469d497bf1d31134cf1a7b8971c5d84141f"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string17 = "58933165962df4ae3312226433df5adb5e646bfce9d0370327b7856faaa4b241"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string18 = "5c426f2a95c86e28b4d2944fce78541c0956fe45eb0b1b728aefe976773b4431"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string19 = "5d08513f61d4172dee626b3287b4f6a9f8eece9fa1a8bfcfc11e85fb9b3d3bff"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string20 = "63790d59bba24d6d5b164d52d837f51bae95f4f6b6337df180c3d7cad3194c73"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string21 = "647c7e069b40a7fcade145d8fe942345e1c18dc54218a85b425ab7f33a868499"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string22 = "6e6f927544ef90a50ee0fc7de48b67a84ab3081ddac08a4872ba922e718be330"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string23 = "7227a5e6e3bde7aab29245076b4c216d366ebbc0a116d4c2286c4bfb226fdd38"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string24 = "72ef1c32661b8307cce495c40dd511c6ff5a55d0c94d82f72224410443172e1f"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string25 = "786585f4258b3ba87767b73a7cb8654ba31967264a82c8e60cbc905f81efa24d"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string26 = "7ba905e8e4cba64f1df56bb1498c21193c9f02a36d86294c761f53bafaadded6"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string27 = "7e1537d35b2a1d993bda4eb5531d479f19b9381db45fd16a9163703ae7602f44"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string28 = "7f1a5a5648f8105399e932839d8e73274e98349da3765e9cb388c005edad93a2"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string29 = "845d0a088eac7562b0992bc11ad8d6d9b178ce4db581506632051cc2a6d8a782"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string30 = "89fb415ca8b0055c8d4af09cf603469e36cb256899d7e0eca024e3f555f5513b"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string31 = "8af3cfb3abdb8084e68290f3f14d0656b45dcb2f35e47ae1641666bc18f1f114"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string32 = "8d2bb3201ed9277b0e4ec42e1aa56ec10bf05bcfcc4ad966656c428ac556d2e5"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string33 = "8d3af0da4c96ce9497da87a6264e081ee9119f6f82bd3923d01e40250690ab6a"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string34 = "98fd92a470168082d4a64840e28e80f6cc114969d1f9c9deb2bc9585438ba9e2"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string35 = "a808917e807c51f703c084d74daf008a759a97f7b1719c40e2453a1b71a39a01"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string36 = "ae153d08924fd9da1a2419a7cabf75db4eba8996ebd7552d5a4742b7e4d2df45"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string37 = "b58a654ad8e0c13d821b1c88a84ce3d9a436a563f8c9c5063b2dae0184b91b22"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string38 = "bb3ef2dc534defdd43d7fd9968db67ca726d701c78dfd420a0b8ef9520d69daf"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string39 = "c0bc9dc5055dc5d03e482e09afede681ccedea676c75958b22b85687f3a863a9"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string40 = "c3c1f7819a3b5421a91af3f491e61eb49506c0a573f1583d66f0f178891a1a74"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string41 = "c8f3081d43f87186ea9413304d6f0edc75c4d78682a3b844f7754dbf40b4a548"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string42 = "c93370cc4ea9cd3e11dd4c24884e8d91a3c062e739ca5a33eabf8ed19a15b92f"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string43 = "d07bc5045b8309245debb4c48cf0854f3b43d24cc3b19618154645abe80129b4"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string44 = "d5d6d92f2c1c606b8717b9ed1027b806adfdb8f7eb32eadbb122b5f8094edaad"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string45 = "d7538d432a986c9f7006dfb742ed5f1673bea600c14da5168f38abf44f405896"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string46 = "d8794a5b30966e2a66827976cbba7a251746c832d27236fc832bd4d309b1ddb6"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string47 = "db8d2fb1a43cab677fc796f9a67f37db52bde8a8778db7489903baad1b7ad29b"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string48 = "dd09fce7013555b0f00b3ec47a56274ff29dafd26922c60ef0a331b4d5d299f8"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string49 = "df715721574b532f4f6afea2a3864a11d7d2ce94872267f640d688a34d0d0625"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string50 = "e200d8dc85bb86dbaea7479accc22dbb5a80776d45a5f7d156816db9faffdfb3"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string51 = "e572430caf64c4499a1ce4230435438d65a9c40afb1eb0ba2f6209806c19e7fc"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string52 = "ee0833e987b03dea01e4261379eab657b48ee2d91e904e079497e263da68a1e1"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string53 = "eee3c34bbbc0f04309c2faec56793615c2811e2ac00f6819399edd7628386411"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string54 = "fe6a409a936601232cf6d934c8fbf97509086c77026490bbf1d6f795091a006f"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string55 = /https\:\/\/trufflesecurity\.com\/canaries/
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string56 = "trufflehog filesystem "
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string57 = "trufflehog gcs --project-id="
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string58 = /trufflehog\sgit\shttps\:\/\/github\.com\//
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string59 = "trufflehog github --org="
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string60 = "trufflehog github --repo="
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string61 = "trufflehog s3 --bucket="
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string62 = "trufflehog s3 --role-arn="
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string63 = "trufflesecurity/trufflehog"
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string64 = "W2RlZmF1bHRdCmF3c19hY2Nlc3Nfa2V5X2lkID0gQUtJQTM1T0hYMkRTT1pHNjQ3TkgKYXdzX3NlY3JldF9hY2Nlc3Nfa2V5ID0gUXk5OVMrWkIvQ1dsRk50eFBBaWQ3Z0d6dnNyWGhCQjd1ckFDQUxwWgpvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg=="
        // Description: Searches through git repositories for secrets. digging deep into commit history and branches. This is effective at finding secrets accidentally committed.
        // Reference: https://github.com/dxa4481/truffleHog
        $string65 = "W2RlZmF1bHRdCmF3c19zZWNyZXRfYWNjZXNzX2tleSA9IFF5OTlTK1pCL0NXbEZOdHhQQWlkN2dHenZzclhoQkI3dXJBQ0FMcFoKYXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMzVPSFgyRFNPWkc2NDdOSApvdXRwdXQgPSBqc29uCnJlZ2lvbiA9IHVzLWVhc3QtMg=="

    condition:
        any of them
}
