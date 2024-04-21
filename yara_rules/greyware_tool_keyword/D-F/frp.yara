rule frp
{
    meta:
        description = "Detection patterns for the tool 'frp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "frp"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string1 = /\/frp\.git/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string2 = /\/frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string3 = /\/frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string4 = /\/frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string5 = /\/frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string6 = /\/frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string7 = /\/frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string8 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string9 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string10 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string11 = /\/frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string12 = /\/frpc\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string13 = /\/frps\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string14 = /\\frp_0\..{0,1000}\..{0,1000}_darwin_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string15 = /\\frp_0\..{0,1000}\..{0,1000}_darwin_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string16 = /\\frp_0\..{0,1000}\..{0,1000}_freebsd_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string17 = /\\frp_0\..{0,1000}\..{0,1000}_linux_amd64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string18 = /\\frp_0\..{0,1000}\..{0,1000}_linux_arm\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string19 = /\\frp_0\..{0,1000}\..{0,1000}_linux_arm64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string20 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string21 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips64\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string22 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mips64le\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string23 = /\\frp_0\..{0,1000}\..{0,1000}_linux_mipsle\.tar\.gz/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string24 = /\\frpc\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string25 = /\\frps\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string26 = /00c526bdfae8fe448b1810c1c06b2827efa1158b7e324aa69c23a57a8b29f603/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string27 = /00ffd863c32645660a29db758db4ea89f7c3eb616b3488cceca55345d8a5d11d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string28 = /0108697c36c88f6ae776f923064236f4e890f3c887a94e798222e5ba3c08c568/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string29 = /025bf967e37ce095f31bc45d886156d365a0e9dc7aa0e7f3bbc91bd1c9717145/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string30 = /02a4baaefa38ed6bed90fd59076be5eceab98f6d08a83aa3b459e160299389e2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string31 = /02ebe0a81dac898bf7bfced875656ec1f05b4eeaf4ba704c8a2b6c88582026ab/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string32 = /030544b09aff990592772ae508a62396c5648a267a14e5f2fad08324c3d9eb9a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string33 = /0314135de58db11f0c6f360113b3f76735e20a7b3cdb928f9acdb0a82ce927e0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string34 = /03dae058d9b192aab4e119e620c40253f7693bfae095820ddd0313403d207d82/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string35 = /03fce0574a2df7993efff8bf3d1e45250b08692081cff53dfd266745db772f27/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string36 = /042fa197c0f91b27404c086eabfb62dad3ffaaad7101046f518abf58ae42ee1b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string37 = /043cd981e81f756123ea4501569ad8d1fbb8166d1046b349ca423aa6ddc0ce31/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string38 = /0476f68f4552ae460d72f0b6c2c9fd4b6fb8dfdbafdec62695f02996d7221f81/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string39 = /04d9eaf4997d1407feca0324beedaca577c63fa900ef04e6a97de9e8e2391e34/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string40 = /05cea2ca577a0dc7a1b8e6393547442174c1035818791f2a4e784471ab9dfcf0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string41 = /05e2ba6184dcebe6fa334c2a1d4534433e8ff9372636ff98eef96e414212903c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string42 = /0679e059dfca6cd022caf808ffe2709207377463a31ccddee1bcb75c161b341c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string43 = /076d9ce5c8644dbeb313e2d90349ad33d3b718b2701899480573266b3f6f0e6a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string44 = /07a0651b2053508bab9370df884096effa653cb24cfd8c454c438b15971ece63/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string45 = /081e0f8ba995218e30ad3c0fa7a12493f17dcbbbac73fdae4391fddf8af2f918/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string46 = /084d3c601a9f5d100ad3be26d94b643f2843fa64dcc5f2f2057c612bf7f9d4f1/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string47 = /08589a1a9ab1159cdd8a156c28bf19b64c0587bd9a415affd19a15ea86441d06/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string48 = /09329200234dd56722e095ee5b0b3d31bf8d39f3bdacb4a473b9144a7e8e8b7d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string49 = /0950dbcd22a110b50c7636f2ff7ca73ee120568d375d75539546c6590cd75ce9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string50 = /09e451ce640afddb9ba25ed619bf2b26b8d080dbf3d09a3ac22f4d365d7832d3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string51 = /0ac137ea9061aea6b6e8e5fc228b1082e14d3e29cafe6103f542ac4ffd728843/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string52 = /0b938c1c8389829602f511b4d8ebbe8f6d2ae6fb4e5a88540b1699c922a63610/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string53 = /0bf96f473385bbeb64faad3caec3ad721187b328f2228820e49838e187da0e22/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string54 = /0ccc051693da612b7c4eed265598d3c8878019cb21e6ec9e3869f94b93e6ca80/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string55 = /0cd33dcfe9a38441eda2c60675f05ab3c3875b1e54608583d50d0835c567a30e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string56 = /0d05e3ebd2490c026e1b8f6780d901eedde65562af02acf3bf80d729a2aae52b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string57 = /0e8f1915a1e2b1b2d37b11e831e49fb5f5fc2a14eea086f7ea5a1e4112095728/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string58 = /0f7acf26d92d39a2e3965ee91bf60e7c331844a1d7e81078ede526cf0459eccd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string59 = /0fd011fb817fa36fe8735e3d97df523970d9be4f56f0848840f737b63ba37fbf/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string60 = /1084631215170fc83b2de13f156a3b0e2ea02f2a0955fc94d3c6c5015391922c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string61 = /11f2af35bdaa799a38a180a1b73083d68843cf731ecea118a33597a14289589e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string62 = /125f87d334addd8ec7dacaf2a321a9f1c9a8b31c8a673d2d02808162cd67f997/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string63 = /13102618f84a2efa07a90733d9bae72e48b897c29f4df4b38bdacebb99517e52/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string64 = /136cc6be28c798b2493875f498b5956a876c24cdbd028773aa9194c8bd846442/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string65 = /13ac5e018ec166c098c2d67635068ad1b18247aaf02a8537532f52b4fda2dd29/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string66 = /13f227bc915c43961e1f3831f155c6934e7d5a65434af3b29bf494b1d5d276b7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string67 = /140fc748db03438c09c3fe5def7e4ef2b273462d567a851addc97728fc8a2fcd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string68 = /1411f74ca4f05e63963448b9d0c972e16cbf98ba81864e1c04de0492ebd0c6fa/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string69 = /14c37cbee05947b2c67fe8064c132652b363c8b0d72fa401ddaf93efdc9538e3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string70 = /176cc43f9796b4b47ad831a03ef5093fbe954caa2a088e136941aea93e0f6a70/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string71 = /1837335417e0bfa4c1caf7ce94047e1ba8020983c246b25679dc5efced9dae75/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string72 = /183ee0c672409cdd8b421f31e2b81753a4713bee962e1edf97f1455cda97173d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string73 = /184669dc9168ac60ebc0afc08ca54473d9e6de933b731cb914f5d4ad836516c4/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string74 = /18740144d6c91dea850c695590973733ababc0634ca18073d2faec296f572b07/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string75 = /18b6a345f7d4fb9250b8d751a99f58a0a2daace02a1f7a4e7bb567237e681335/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string76 = /18ee2a78c352eeceb07d55ba572955af64b14282914fe77edf632baf4ce0f967/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string77 = /19ca9f2b318ea2efbe9f2b213c2edd68de54c7ed35dc3f291146c67374d8c57d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string78 = /1a1a729fe607c59dae787bc5322efcf8cc5a9e87623c6d10e2a08531829bb9fb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string79 = /1a527c78ae25fa3e393d70fbfcea5b928ca96a689d8e82477f1b0db0cfc51e76/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string80 = /1a8d2c5bfe3a0367068cdf890b025258e5614c3fef308985c001500902692817/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string81 = /1b3c61129cf7b45ad41a6b297f4425b9e700cf6302c8969232c7587ae7e727d9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string82 = /1ca8187c73c3c75ace29675193659f9d6ddff3e5ddf2131f49f156844ca7d778/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string83 = /1cda556f00b20f5b575ba40f83d8a007a8fa3308ef502c62fb7510989c3b7b10/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string84 = /1d5b17f54911bc22816b0d72b32c258b259eb912d9d0484fdc949a315f5a5d42/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string85 = /1e5b997597bacce1d971b83416c2f8c9cde0cbd294e6b11d91a3939f9c6356a9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string86 = /1f1eefdf6a9ade3923edcd716c56941f2755848a4bd97167aaa1ceebfed95194/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string87 = /1fe64b366408022e4d61c1e37f64e268f7e72f4d351425df36c35fb1cfc534fd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string88 = /200244a2c1bc9e186f875c23d0b78c9ab59a88052f4f4132e5c28a70fdc356b6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string89 = /214801dc012036d847beecbb5c2a03f64bfc50d601f79da86a4a783fc0323273/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string90 = /21b32cdaf6e4c74a88a0b6c3c377a3d40a23f73c0313625fa63ba4a6542616fe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string91 = /21d0ed799e2d277a941a92a68b69a1ad4cdfe058fbdc6cb6141fff2c81421c57/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string92 = /220583e20edd98369dbe929d215a387ceea937b0e0637f62558506b2a6c603a2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string93 = /22c7719b9a9d0ba2a43e85623677983dc550957a9f1d855994eb33d2e4db913e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string94 = /22df14e317c351bda4bfaf256c46b6ec281304135ea24c00bb2a71a5e14d4f22/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string95 = /2330aca22b29fd0298adffe2e57f8eeea5837f09abdcbf11b58c128249d2f89f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string96 = /23705712274935b9b223412bf731ecd672dcc8b5d0c11a39372aacedaa6a66a4/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string97 = /2379c3dc7bf783334051c06aec97ffb50007c9d17572aae45500f07c764ab99a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string98 = /23bafd6bf4ac0e631b37bcdc68827f4b36f06c3dcf0bd754f5d0f9acb4606a3b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string99 = /24395170dfc41544eceeb78529c8de5b57b65250c27a02e058cd013e6f66097f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string100 = /24fccce2e9c6684480bfd8ac0e9ea3e36d4203922fa5a39ae9f63bc0542f68f5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string101 = /25431755a121c12dab3c28fec18eaef027a73aa5e9780b33f6801e152e42ab36/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string102 = /26acab3487be8980460ef86f0fdc7a446cfdadab02a5a0b27dc760ecce15ffc2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string103 = /26c48aa4fa4458ad29d0de364904e24be40424d4f6c37005c2c2d9c6e41e2b06/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string104 = /26eb992318437fad2d122ef76cfb3086f1339201486a1cdec910fe1a457ac383/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string105 = /275b254a20dfda754d6aba28d335a392df74150d6945d2da20a7c5718dc2c001/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string106 = /2809d84eb3f9bbc8bb73596d8826e112ebb455aa6228ff0eeff28dc6264ef6e6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string107 = /291fa7918aa575802ced2fb77e45f33a3cf7fc4b5c27c4ac31a68b2506c50a30/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string108 = /2ab7b66c09391d9d76bd7a4818e85fb3818a10a46c91a804b982d7d4c9fddce3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string109 = /2c02d8f219e83bea4bb4c9ddf1222bdabc068f656992e967dc702e70a1aafd80/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string110 = /2d07711a0e24e3da968ad69aeeb458854572788e7869d276fcfb1189c824f9ff/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string111 = /2df23e00a1d18a2291f17cbea17c1e4981e43ed09de3608197bb9a62c104c553/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string112 = /2e1a85c3cfa7cbbcb8747f53de4d7c913cd8ace7475988d823ca0e30bdcfa44e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string113 = /2e935829f4623f148f3d97424f8863452ac19cf2edc1a659af7500428b894b47/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string114 = /2fae90ae2544f8b46582cfb7d46984d837b193601b35aa9d63c2f4f52007e32b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string115 = /30199cd67bbed08c65f86c2420f0967491cad2ec791c97936666bc930d65e73e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string116 = /30b14705cdfcc4fbc654b55863d110a99deaa92a1490561e8dfd84326f9a9e9c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string117 = /3262dee2fa68eb8d9428d209b2e87c2293d007529898850874b19707088c416e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string118 = /32665745aaf03d263a9ce87f0ea7a17eb3476328c25c1a1fcccd0925934f7313/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string119 = /33893a93b57e6509132b4d6ae29f3e8a1f4c105c21746f0f0f036df0cf8d1979/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string120 = /33e46384b3caa71163ac79470de2af0cca5f8ea7593a9c9ea4e714dd66c099f5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string121 = /351b90825fb48695f36208f0e6cfbbd53f9539306119b5ca0aeb949bd255066a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string122 = /35386af9e43ed1948faa7037050573eda3299d4a11061734fce5f4be51c56dd3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string123 = /36ea25323b263a1ac1d300a2bd8267905eaa7d752fd9e7d7b4ec40f836c737a6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string124 = /3961db6d3c5951da49b40cfdae22c8fd53ea87a2ff97245d8aadd4d4206c6fea/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string125 = /3b9f8b80f13f20194490851b076186124b67b9a7845b32e5e035ae4aed2e45dc/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string126 = /3c4e769a29f03bcc9e998adcd1281142abfb5ff1dd66da5a435830a1cff34217/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string127 = /3c582f611716c77db5e4f69823fc72572006608f63d9859dea598f0dfc74ed0b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string128 = /3c9e03e28899ba18e42f51006f7d94192fbae009885fd91cfc75b354cffebf58/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string129 = /3cc79f9fc44300aed80988b31845328b428c0999572eb7f1df949eccee0f518e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string130 = /3cd7ec9209b973520d47d784a09a368bfb9e2bb195f3c543ae5311720249e315/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string131 = /3ce4df319c7ea35f8cfa13d1e03a0309fc4f57aeaaa02d05fb9fd560443e67ba/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string132 = /3f75d981d58670ce7e0e3f5ead2bd3359cdd1f33b96da726c62013567a884639/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string133 = /3f9462f9c7aad6fec22159529b1db7382acd7254605894fbc44c7a7c464e148b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string134 = /3fabb19b2157709cb6baea755513f38b2d5674539b54f7853454c48c5a9f22bf/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string135 = /3fcf04657f8efd6c6418047bb8c219878c913c4bdc678a8c4bbc8a49d3a389d1/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string136 = /3fd70ccfab20e75b8517627ec58e30b33003a24ca4629ed42650ef1b98f17e7d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string137 = /40d5025cb0b0a6f26cc79fd23fc78ccdfa050bd7e80d694f2039ab98093f831d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string138 = /410422844c6e562b64f05a07c069860f94c5da5e3971409a1159e066bb450158/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string139 = /41a3a760ab0e04271f8bee1fd80011ce8e93a8455f78919864bcb13200f758f5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string140 = /41c75d72848375144e46b9b9fe56168f365ce4bee56280757dada6c92bb8abc0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string141 = /41f1014ee2ee7ed0a6e989deb937af9a8c01f4974fc1ef541583065475511d65/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string142 = /429aab2804d7431f684c6d409342af57381dbcafc4b37c49606063be2f92d4a3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string143 = /429b1032624f2fa211d31521f1d7f3703c022e476f6e225325842500eb3a37c6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string144 = /43534e7300dc4de9b8dc796f15ff168eb017fd8e895ad73b183ce71dbe0b9beb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string145 = /45f65dafd172f3a5e05eabf3d4efbb954c92a88851a027f79c19f61a10b78287/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string146 = /4669cb8c374ff0ec48c0f6d15a939c59390c2109645914dd52d4deca519c084d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string147 = /466fba9c2e3bb99aaaa0041443a360a4fef5ccbb869e995b8f60dc0a3ef70e08/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string148 = /46b6b8e83ccbbbc2e639c852dae9a41e79f8523d444fe39f9d8f7cc5e7661081/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string149 = /4794997fffc632dd8d357e9d00ca616e9efb2741e0f0acd1599f90be6281b9e6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string150 = /4aed98c21ef4534951b6faeab4982376695ae1e10ca90aedd27a9bfcf6caea2e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string151 = /4af6b42eb79a5290d1e24e534a0ec34521dc2d30ef60898abd092ddb2e1cd55c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string152 = /4c12c1e287a1fcf28bb7a542fc5c355c42bd8e65db20f7a8b77d58edae502af4/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string153 = /4c3e156680341f87566f7534124d9fc6ef687a86873eee9f8214049cb5588242/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string154 = /4c4685aec2af6e71912d9d29a9692e0ac6bbb1926f17e6b6ed680cf4e9ad8e5d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string155 = /4c90633d523f467384a424bbfce211f737becbc7c4ac637e10e6c91fda8a6a26/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string156 = /4cafe6451efd64e50a28f2533055b1f68fc59426838214d20341acba515b0eb5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string157 = /4cdca1cc3d298a5e6628ec40e174882e26039d953492eaef6c0d25cef065ace5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string158 = /4ce2100f0e9907d9dc152f94f56bf33bc44d029b2f83efde32b586a57bf55809/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string159 = /4d13675c330ca07d532f7a2ebc72fdc011487fe318f2ee645842a3fa4b23c966/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string160 = /4e155fcf4f0c7e186ccd2be94a2e036bb62790c9bc00d9145a2999b5e3f38717/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string161 = /4e2b06bd978472dd092c166b43ec56ab22c1347710fd77616283d2c27ee9ae56/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string162 = /4eecced7aa167279bda23afe2be0f3dd9b61080531fdbae5137bd257c334992a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string163 = /4ef082c1788e972f016f00286a2054c82189cec3a1a3e2af8123240c2888b6ff/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string164 = /4f2088aff3460c9bd278121de7781985734969399d408f0c9e3f794165e0a407/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string165 = /4faed559dc80bc2bf43b6c3da60e19f86c42ab8ed2b19e3ff0d3f4e4cca6c50c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string166 = /5099b8acb17c0681301d82362c9c37bb9a579bf0580ab7362ab7cae2b7bb5f68/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string167 = /50addce2b6170aae470a9d692f444825991e3c1b6208d141c17ae5909c6c2cc9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string168 = /52fabafac257ef8ca28e53cc4f210789cfd882946d0f9d2f9457d63f0344a602/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string169 = /531be6e910202087c61e10e57e28eee9a079fee380b8a42432de55d570bb25cb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string170 = /53242fd2bad1e6b3039fdef38df6219710864d1c9e639208a2106326921d15fd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string171 = /54e364bf382cc987a962fa5db328ce8bc375bff74ff7b8afcaeb1905a295e027/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string172 = /550e7d04aa4d00fb81b1cd566c58b056a3da8bcfd05631e5f4edd673232b9062/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string173 = /572872fec378f423b141faa205b44faa07bbf06f7272b0a6a3235c7992a69998/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string174 = /5953e84b6a1590568b6d77a0b75093552577aa61484aff41b3ad0fb35c68719f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string175 = /59b2d72c684e869bb6d4a5d37bb1c165c0c4432f20a6f4204ae6e7de1e632587/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string176 = /5ad396bc221aefa47d1192d6df11193240891ea3a88d0f0b941e1cb2967e2a01/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string177 = /5b4204056ae94aa8281218656a1b3566eaaea2ddf4874eccb4a9c23cf9bc0fd0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string178 = /5b7c15f9e14042a99c38515ddfa694f188f59d72bde10ce341d86cbf7f801b19/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string179 = /5b8d4fddcbe0c9e1e82bf8ca30b97bde3fff668741e49a260d6c13c55584bbc9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string180 = /5c4828f6e89b6f2479b671d3e7644b34b6968a6017cac402144c844b48dcc621/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string181 = /5dbe659f612640086d3a7dc05b397f4e444c92d784951c49bfe4020b934cb559/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string182 = /5de51fda0577a049945e42f386df70a8e9eb2769af96bb6b7471cb5072605be0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string183 = /5e041b19ba9ca6a5255679b353099946065edfdf951d807db2587fa8c95b1447/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string184 = /5eb942ba9ed0d45d2ac1ea6ed02fbff802a69c408c8eb68155dd2fb7c6fabb0e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string185 = /5f1660b704a8b580082b81e14a41d2da9ff1edeebc59b885acb92f1ab1f46838/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string186 = /5f3f60a71fa040a36be5de818e6f95c48e8a2ba368b700a079b593f0e281dbd8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string187 = /5f7c9ad77e37a5921450c013b9792dac4ea5ef5d3114ea9276585f62e2318a79/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string188 = /5fc4a7caff50594c717e7d8e5929d4cb3e1674d81fd345a29abadce0a86d22f3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string189 = /5feca5a4d601ed393a3cc04d8bf3c41194ef56af155c326cf1e7fdfd130ef17a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string190 = /60ee29ebb3683135c815b4e9b6681c92a445ac3f40e9302a70b65fca68ff5116/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string191 = /618b1a0d2bfebc9bc3e59b4c39e67082a445e5aeaaaa0fec9eded436dd64a2d4/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string192 = /61b4d21b669ceb671b298a4ed4aa3c70b33d6e3e4281f7417336a76f684424ca/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string193 = /62044b03a7bccb7e8f8f4f691f34838cd1160a643c0bb06ca8489e78d2d65897/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string194 = /62170484c4d450fa47d86ed8b1dd20659b22cd7bc5a36caab330f244d6ea4d97/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string195 = /629d2edde798217cc664abb52610531e8bfd089b54879139c66a148429897e11/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string196 = /63035108f37cc80d6043c1fcac50f8e856791a4fb8bcef0e792d97c88d8e35c5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string197 = /6387e119ac3d0e3ec269a4f6569372a57f78b0545d5af71a70c42e546b2d6dc0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string198 = /662d62af7744b9b639b3473bbdd2c4c70dfa5ac5fe1d058d13ce3cc7ea059500/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string199 = /6681551b9bb7311625be8f3a269c183b600e13966787a8b11a8f9e8595a3d66b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string200 = /69c08bae93e16aaf57debbe2b10df6824f5dfef32ce21b5d57d750b0698999ee/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string201 = /6a3e20b001ab57b066a52394ba2d992ae6d93b22260b0969307966fad6214692/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string202 = /6abdb7353ae5562e16d28e1da142f5f97bd51964359901aafd694b4638f85739/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string203 = /6add94e2916fd776bc2fd62a01fa6fd282f040e2f05ba42962e823eac821ae81/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string204 = /6bef9db4560b6c7da2def271f7bc5bf6988fafa3e654f8a2bfb589fd7d79b2db/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string205 = /6c9628cb8382894dc0a928df8fcea9dad9cb763ff161e31f94f816443c7419e0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string206 = /6fe6b708ab65d61293fb7f1669a3dceab6d8a7d06f9f9b93db68025873f51c44/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string207 = /70f57deb3ce57eb890104fe14d6fe442a815e095122a9c2b584e34d3c54f5563/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string208 = /7174a1328325da89ed6aabcf522131db9928222154e9607b0d5a2f7b2977ae93/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string209 = /718c0f0820f65782bc19af479f2406c9654fc564b9999a0936581b4ed1d91bb2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string210 = /71a0f3137f02da4116ea2b7d134c38be86a1229cffb0b1dac4469b561ea35985/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string211 = /722d7c6b976d85f29acd429f1fd6289a6e8451a3e1815444404bd4b99eb553f7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string212 = /72c007c9121974c0812eb2f98e26f987be28774b3175325d45596a555bfb811a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string213 = /73f3e7037e5f06e8f6fc30aa47aabbc815b4173decdcab149c647126a4aa6370/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string214 = /7402fc76816fd653bbe050a3f8a2dfd7c1363c980e2cc3dc369c60c3f0d502a7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string215 = /74df509decd6953a77543ae8febcdc05379bb2bd0614ad2fe53a4a6cfac86caf/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string216 = /754d66a918d3550c83e670a458f66954eec0521d6e76a20dd0a865992ad1b55e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string217 = /76c7a4f5e35f32b726c48fdd32e292f63c7b374ba019a28dc44b04140f03e6de/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string218 = /76d2a7bc7ceb5f542ed5be5208f68253261a36d1f4206fc4689296d9033a59a2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string219 = /76e5d42d4d2971de51de652417cfe38461ef9e18672e1070a1138910c8448a2f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string220 = /786985d9671f485f045b1039b98d312e5d97c85b38b116f5087e5c95d831e455/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string221 = /7946d13b2498410bf9fb0cc32fee7ea44bde8be438eb1b1bc67c440a3671589d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string222 = /795defca4853f7cded6625d792eae33b45987856b961a82c8b6cc44a8d0b3bc7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string223 = /7a9fd341e0deb467ba0ab4913852adc965a0df2ba38e18ec80ab7ef61a9e99e8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string224 = /7b6c9cf91ad9d00385d47139ffc69c0c9d72270886dbdb4f71f599efaec2cb64/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string225 = /7bb651eec86e0126af3bd515235901a64b5490115defa10972e703c05bc65345/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string226 = /7c1416256f7f3637e0dfed99988d08282ae0866784f1eecd53a3639e1a942867/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string227 = /7c55322bb55e4085ab950711f0c3406a25f95573f618ed347e8f542ecf93cb78/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string228 = /7c6208a3f7131802f24ad7bf7f02c760bba5c17443bdf328598d0758865f80df/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string229 = /7d299b5695b0076b24e93928bad255f76c8352b5002fd459ef63c0199251abe9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string230 = /7dba4f6e942502f0eca2ec37206671734eeb87c40a29f16b96ce14045da9e833/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string231 = /7ebff99259931e26c3baf8dd78c1af671d73a6c91a1d6ec9107c0c225df76bf0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string232 = /7fac327360b72613dec67583e4b939b65af0b88b676660821647b161ec2173fd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string233 = /7ff954d3f9f0d655be5f250ca50e8b065ddb8b4d3a1da0a55f740cc03301c6f5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string234 = /801a1ea2bf02b9ff657c34708918397bec61408bed216f6ed45889973ee09a01/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string235 = /80228ba9bd43db42713f682032c0d4c2faa07ecb01be848bb57f6d51f24fa138/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string236 = /8141072eb367f6cc492bbcec66c0f08351398ba1a5b44e9f0a831b382ef866cd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string237 = /81930048c93d8db07af024cd0355809248501dec0ce182a734d16e6bd48055a3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string238 = /8355cecbe4792077c4977def67d9d10be79d0c9442aec7dc93cbdf9523387844/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string239 = /85cd761d170a2b9d567dcf7bd8c1a4aefa19aa9cfca048edd29483a196b42dcb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string240 = /8805d70a692b0c5e20271214af085ffc3d8ea2176ce5dbe06fd6e4de59d8206f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string241 = /886ac7c8c0e01bddcb808947f76a5f904572e337fa4023cce4bad71a7ae9ca1c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string242 = /895b5c7ece8b458dff80ed790fc1633675a05fc9c4bd994ac89cf8e9d83bd32b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string243 = /8a0f1ef0b8723089613e2754d965ac9059eed027064bdd484f417fa6f5756d12/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string244 = /8a222ae6ff9a59164b44aac7d3005e4d75bd97997c48a51e05b5d50dbe6983af/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string245 = /8a5b86e7ea67bd1355ca5b9ddda60ecfdfb7c0b13cf06af71c1e72e88371016d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string246 = /8ad8905b9296f3c26632f3bfc66302bc082b62295f6bbbb5b78e31d1e6649f26/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string247 = /8b0067e658dcbb21313ae8192aa7e1d364af8e96aeb7893ba7422ea0844e8bd5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string248 = /8b2aee9d9eabc6078ae8a4c718030be85a13464becdb99f97f635e75425eb63e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string249 = /8c47d8f1ad960d0f0459bd0fae7bc33c9266943d04549145b969c9107c59703f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string250 = /8e05baa844d928b6239bd9f43cd3e065fc2af971930bc6344e2c899d7eea14db/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string251 = /8ecf30ac7c14f85da20c1761c6418979282bff12db4d82ade2f4a1a8037bdf6e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string252 = /9033c6def481bde4bf7f2361966ae0ea92dfda5763a167460dcf0e231a2d02b8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string253 = /91b1b306c1a538dd6d60857a1da9019241034bcaf0cc19e0c07abfaa8f6a8f75/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string254 = /91f46654fd8eae9fcc5a7189c6629a7e4b8f49654d996bbb45432cb4a46ac8f7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string255 = /9299c297f6c75c6aa2bbbb5de27172e367328b6f5bbb6f8d1c4ca73c4c4af415/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string256 = /93afeb34c835796508383b70028216eb3d43b2bf63bb3f7493acd1ec533d588e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string257 = /94169b8d725d30bb0ddf19db73d18b99544dcc52521507419eb7fb42823ea8ac/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string258 = /94ac6a42a165d913b79a0dcfb2d55a686e81b776697580e113aecd8815607076/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string259 = /94e608af6d6f96619de403bf3aed4db8ab602999e0335380279e0d8aca1c6040/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string260 = /954903a1202b2a256a526839733dd2c3e676b58e68817aec11fd60743dab57ee/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string261 = /95583f7a979910ff4e65a5d9802df699063472a67a1f9e6d6fd6c2fcff448a14/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string262 = /95c0695cdf0cd8d399cabdccdff93b25aa7deb97e950bd3702bbbaf9a2baf87a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string263 = /95f0d8c8f4781fc8e42b7d644024c647032e3f6cd0ffe425e8f7d5a46d601557/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string264 = /9704b24b5a58144293f7c7715b095b1ebf43b90e501050dfb9477094e6dca41b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string265 = /9774490a0a4f822960a8da99a214cec6e2320622c2c20cd6b713e0e52806031c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string266 = /97b4d3555734cba2af59b72b960ce10891b584dcf8d9e3db9f4f099c0a64131d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string267 = /987f353f6ea282e259738eeb90c20b70fe20e1a49aca498b02acc47200c082bd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string268 = /98ab35f179091726b739c9fbb6643cc7328076bfbddd09732bb68b1cdf1b7435/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string269 = /99196195845422f6ac5962782fa3676f34fff343e0fed0f354cb6600d894afd8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string270 = /9a12912bfbf7dad0ebe5fb3b0229b318a8670d078137f2384f81c1aa87bc0fb0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string271 = /9a56f4e3bf3a276c7be0b2f180a4d6ffbad1258dc09fe2d6637666dee9c840f6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string272 = /9aab5a4936295d13f2602c8e087fd789a7910b3b3c9a47b9fb799ec99020192b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string273 = /9b3e4c64089c3b78ea1f666f11551e4ae6a435fc0797e39ab4fb07fd633b400c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string274 = /9bc9e19e782030fdd219ef29607658de9b197adc9427cbc4517cb9884b7e7c07/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string275 = /9f27cec3b7e600c0223c0de06b65feafa9ed6bf82a8b1dfe338aef6b03bac097/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string276 = /a003f5539bcf1c36e9d8f0565857dc8478015da4f97fa64bcb91f6495bbfc105/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string277 = /a094d80528b9c413de86e56ff9e8617ff6b8855e8e95bc9c1826dea339033eba/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string278 = /a148f12a5261ef3186322b08cf1b1907d987505ec5485adb290a350bb2083f63/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string279 = /a249c503a622599ba68330f323de22a457e058157cb8e38cd3e59581993c03d2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string280 = /a2a4ca5c8cbd085efefb71b5ff652d12425d6b16cdd3f22426c0a6f32d109942/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string281 = /a343c8f23ba35c943e1c9311df17eb12f84c682d2ba0e965e244a49759b65f28/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string282 = /a3f01a59bca7cb330bf680019595bbbf5f8167494fab4c46eaaf836fdc3a1902/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string283 = /a41466714ba9463978139a62d241893a034425235b61ecf2efd868857e1c83b5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string284 = /a41b7612e1057aff1743cdd0c9cf2dddd07f7e4e0340d419f05c42612b118a02/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string285 = /a4623a06a0787afdbebf56aa1f406229d7457beb36c316e67ea90346e6921bb6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string286 = /a47d75d634790109eaa5768d4e5cb504988e3754dcfe458072ef0b46d9aea419/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string287 = /a4c1317ecb23efbf995cdf4b05c514fcd005d08ea50284e7c5b50f2ae312d88d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string288 = /a4e37ca2c83f78a36945b82a7779749ecbf9661e9e6e4e881ab6d41666e1f669/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string289 = /a5496a0364e4e071aa6a1cbcfd519e35ac8dcb4eac9a24e6a22340c4d4cf1914/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string290 = /a5656349a6b98aba519b6222ad470fdb2a95903ae5ebf0b90819c441cd8dba8b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string291 = /a660a94c158cb280974447efd174d3525d806ac7235f6546abeb1a57660a1125/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string292 = /a7626329b690c269d640555033e156a55cffb967f11556eb782ff130d0ad7982/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string293 = /a77d3fa9419c5dc12ebd94eb5b97be3cff2c12b00dbe3884adc9ffcedf73909e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string294 = /a792cd515589050d475a28b714276a2960ed7ef8e0e5baeea3d38301a775fbb4/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string295 = /acd9f040fc6fb2a595f20bfb4faa66d9244615a0feaf9d2e4b03a994ca126a32/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string296 = /ad151125bd46fb8abf11f2a4347c7c85e102bb0e6128c69962c8d6bf9a71fca6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string297 = /ad61f4285ae98dd4b8bad622888e97bb290e2ca667cd9ad52ad2877cc2ec6807/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string298 = /ad977caa79c00c082206f46f521b8f99a44a051425dbb69ec9da1a152aac6279/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string299 = /adbfe65938517a8024565569825526643eac2d3294f4524d12a2846611107e08/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string300 = /aff5412e89e7164b5083909f2b5a81d8edaa644a3bb6ef696843a6ee0d129fc3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string301 = /b09684adfae58733bc12cd0ee3cf1e20d6b888c3e5280cf9f9e7a6467cf87a71/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string302 = /b09d38e5eba230a6bb04f144f5d32d26ce69f1424bbbb1058d43c712ff558679/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string303 = /b117ea60954ad0c8d4e92eb60ca8e748806978506c377d59b4f5bc5295c4e3d1/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string304 = /b18153bc7a6d6627f402380a6e5ac01b631207df54d7fcc0d89a8f6f81521401/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string305 = /b1c9ee1dff229639c43c60e39a6023798b5c96ccd38df7e3edd41cfb6990c90a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string306 = /b1dc5923bfb2c9d0d1e271e20cce3615f8d23d276e376d9c566dc5400f14282d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string307 = /b2768608b33e964fc7067657f385ba15a69762b0a875db47981953d70dd36af7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string308 = /b2cb915a6e66c99fcceceae07b08d28002c575a3bc2c6aa8ea88c9ae45294be3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string309 = /b330c29f6ef91302c6a2b9a0f6e86c77b498d0babb60fe182440f1b97e0554cb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string310 = /b430c31a107a7c5e48899e3ee800f39aa50300d3d76f87bb7afb7ede58875cfe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string311 = /b48943e9641fde4b91e0032fa031599fdbe3f9cebdd8612cec9e3477aecf2866/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string312 = /b4a40bfaca19d5b8570be95ea2839fa82c7814c561510c3e3807ce273ee7c7cf/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string313 = /b509e7d50b164aaa62b30efb189caf965615ce266d51c243e494bca14d2f2864/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string314 = /b53e3cba1a8a3ebaa1e7d04f647eee3aed3417740692e346dc460c813403475c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string315 = /b64b34521d1942f05b9224bb21d025af5c0ae99fa2e2dff635f26f91d91a6188/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string316 = /b68640e6866a22639186095138657c53b0bb6626ec0438b488d1a2ffdde23155/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string317 = /b7a7814aedd230b66e11f3626aa505a2a701d6afc19bc8be2143955bfa3c1d6e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string318 = /b7f2414b1d8be99157e5b25ea578938520c45d094534fffb2e515796559b9b29/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string319 = /b83a269ce5fb9ff099695165a5d3565646f6032579c4bc6925c63fe8100aee0f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string320 = /b8a048ff117640b07633cd2cb357b07ab64fd1817f6f68f9926c555b293d2a69/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string321 = /b8a22f70d3451a7f4b8e1718da28ef02dfb38d37193bcbdc1df39eb52d0da40b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string322 = /b993db8bf609419a850d3233f97bf422de7e5e54576120c36de0ad703e541bf2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string323 = /b9a1a2387b9b07ec6be9d28e5ed9639c1ea29d41a84bc3a62b39ab476459b1ff/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string324 = /b9c79acc881c58b0185465a5ded032d6210637f860712f04ecb800b66453d125/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string325 = /ba4439ded52eb5c5994dd10181ff83ef350933753198e50bf04b5f21333f2a12/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string326 = /bb8734f2be2907a2923aedf43757d6ff85a7c66af789b8dbef34ddaf2194f05f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string327 = /bbb1ab095f30e9ecf1b745579f6ecff80eff11fb712f2bc364a656fbec89f73b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string328 = /bc283cb6e280e5fd5089216c8362003235dcf371e9f99bbc14462a0ef05c0b53/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string329 = /bc886aea03ddb2d4201501904a25816ac962cd3fbe6bc7fab3ca05357069666d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string330 = /bce6f8df72e0f942a3eaeca45ed59fbf929d887b9fcd30350944c5f72287cb73/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string331 = /bf8ab462d70a288b7ff2e9dda8151d16340ec4758843a619a936b7541f52fe54/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string332 = /bf980fa58499e947581c6b89b100d55c1d417fdda6f7544422a4a6400248e20d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string333 = /bfbc703139c2fcf59d2fac2bb4afe3e60dd5f77dc12d84c8f420260f136c6721/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string334 = /c0c02d53dea74824ba7a5a278d5e9974aed9d9d5f988606b9ad3507b8b051a7e/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string335 = /c14ccd69607c34707120e7c2d2df9b6c0a11c7f40e22f116d75838e2038edba3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string336 = /c14d5be9b9d80a48354c04dd1c3f80167abae94a1854d2f5116e4e5a0da89b91/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string337 = /c17291696d623106324b9bad894599325a90148d7d19970b9142a445b789b571/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string338 = /c1b0377ee72dc62221e2c8ecf913a34e230222e86f5291f0813474a4fd7e9b24/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string339 = /c20f8abf5e0933bfd88fa974ad3a005c72f494aafc021916927774ab0ce6ca46/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string340 = /c32b3159a8aa089b08222987a32b9856c046c276898613c75eec62d370df7e01/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string341 = /c35d5b705e2b321cf612bcdeb44ee27392d6a1202248e8ec30bf178adf00f9da/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string342 = /c35dcc7b9549eacce4d5b34a07a3d102b0c631ef4b72682ce0472f65b8777d4a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string343 = /c3b011e15c03348592d4a2adcdb90994e7ed29a43f572945505a429c12645215/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string344 = /c44853992b0d6d3f9f5c777038590ee6a5869dbeb6362dfa5537e9d730aa26f6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string345 = /c53b188ec3eb09f34484d2576f957e61522875c0e7a99e67722d41b2b57cdb4d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string346 = /c57526a8a0010b811b9bd367704125033fc71774f6a66dcfd4224ec5478e0490/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string347 = /c5b32aaedc7785b980be37519d95d0d3dc3ae86b3943bbf2ad7cb5dfc57460f0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string348 = /c671953a8131c23c8039827f79fc96c021aac1e2b6dfff805ee68f490847b3ef/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string349 = /c68f67a262cf61a81945326e0e0c9e2a3dce209c3125bb0f05a16921141f4231/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string350 = /c6f00c7458e7546b9339ce65805b2969abf55f95698f0b2f0904ed85f187b3fa/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string351 = /c7b22ed0a87596cd839b555e4992d80691359e75409063b6dca2dda96e7da480/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string352 = /c842849be22802e6500167fc34fac869c584ad1f70b6c56dcc66d7391171d567/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string353 = /c87ffc18bfa386cf946156f91fb8649a0cdbcd762550a0b8ab1f4774cb608455/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string354 = /c992b9a8a53c53465f035d5e254ecc1a9455f260fd110fe1600d5da4a37df413/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string355 = /ca1f8ec6c7236e7c9c31c1c40626c05a597e3bc6f647c1325439e2f825da9aee/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string356 = /ca7baeb243b5c264847067f6e5619311223f1741f73d5371ff7fa90698ff5a3b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string357 = /cac2bc6fccb071789d7acc95f02470cfb935cfc9c7c6a1e6d91457e4ff11e8e1/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string358 = /cc928db0c984d3a7e9822ebb7ac897ddb90f43848488a5c3261b5704085fa92a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string359 = /cd1cdad2d88d638a820cac9c562bccba8dbbc42d3ac1ec8482d12105325a3adc/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string360 = /ce18273ca20bd38c567b0355ca2c85575651b39249294969daa51e568077a872/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string361 = /ce70a9a044271be4336d7376aa1d5c5f8de8497b1e284b083f6d2184d6f57042/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string362 = /cf5cc61f68d705860538b8d3e865ae026a7b27e4da8c1c1a3f50c5e7827cd097/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string363 = /cf873001de9c33445213818c5844992e1a3a02486bd3defce556b95e9b0f4af0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string364 = /cfc766cc82568e40d7198493340283cc0f4f42de97463aef863170f7e773ff9c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string365 = /d1d9b02741e5d8742853665aad6a36a74a977fb82108b894712008db8d170276/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string366 = /d21b617081093f98de5fc1e57700d4a104df67c4965f3fb99dc2650aefbce86f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string367 = /d33d83e8b98ce5413603f71b1c0b38c1b5bbe1d1c826b7ada84a7543a6cc6ea6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string368 = /d3a481b40889bf4c6fd35b18941de04ddaa2316ad51977a5af7bdddf3650f808/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string369 = /d458887ece9050b08d1d58c2718110643b87f254981cda6c86f25dd5559e3867/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string370 = /d458d70dd88048d1fc898d5422ed570e912d3f3ef3ee5928871438a08514f725/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string371 = /d48623a74a00577be0409d912f8197a110f13192eab99d3959ceb11496ed0903/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string372 = /d5d2ee272caa314a731dcc59ed4474c9f34953c617e8c29fdd86ea8c017f2e91/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string373 = /d6373caf2bb26e7956c976d7d9142a082a0c259525bac3d5bb2fcfcbbfa63bc6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string374 = /d63b7a3365a5374daa0f9418d26334c3e913d762599071d1d7e629b2e675e4e7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string375 = /d7a7a6085fa6a9f8de0ae2c221c1ef110b9afc2a0122a058482ef3974d031ac0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string376 = /d7c2ffe601af16d168d881b88817df81e9bc8646e56643545bd9a11f01ebac6a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string377 = /daf162e5cc90599aab036b7bb4ed6d4c521b2f5732a6cb40b08a00e6714deaa3/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string378 = /db2975501126fc0f61097acdff7484655e5d37b01de8c509c2c5e0e88591fb42/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string379 = /db53bdef3b270e45fb9efc489af2948be7c7fa1e3a5cae9698f2832e628bcd3b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string380 = /db778fca7bf230b926b5ebb34d3b97bb3be5a89bec8254f824ccdd57ba2b31e8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string381 = /db80349f17c39f502a631afda7cf5b95b2a85cdcafa92359b9f4d0375772c440/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string382 = /dc3220af2b22469da26209d4b376858c11160127e83bce09f85cd0c27a44d5d0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string383 = /dd781cfd710345cca2df4d306245298efb61dc447d8004dd5542c1b2083e39a7/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string384 = /dd8057968d3560e9ecb42b2ed50b796ec09573d5263f689c8e0633a8b8a7127a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string385 = /de3397d1084686a5ab9f82fae2aa65f417cef7d7c2cc12f7eb9da51c0a404de6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string386 = /de6262f886175411573c98fe2d5838449b4fc2472a07748964159a468ed0ccdf/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string387 = /df37d932eb846e608187b0aca6d182467ff24c548a044b9206a93913ec93c752/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string388 = /df7356db409cc406294211063bf387a8b590289370811b1d10d6fdd1023c3250/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string389 = /dfd7bc3410c018dc8bcf897696ddfb10e7aaf5a584b8220ae3949ec87205ea4c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string390 = /e0b8976e986ef0ed0901560810a81cc80cf8c332e087edd35f50e9a5a88c79ae/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string391 = /e195429f06e01890fa50719ead4dfdc338b80c9703f6d6c7b9e12c234ff2f39f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string392 = /e2047b43e87456568a505b84c45f52e0d2ed146896ec1e3fceb72e818200f11f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string393 = /e20d90b0670c637a65125f89467170efb3fc227a78f44ee585a6d3fb55b6a881/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string394 = /e2a6179880b852366edc395685fa0e82eec542e9c8a2c3483d30d5740941a0e0/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string395 = /e2dd4933cc48caba288be96ba5b226c7edb5be940c0452d9bc7faa28ab66847f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string396 = /e2f75360702bcdc390997de7b2557f21a1f28d7ebd4d1ca74cf2e38849185bcb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string397 = /e33075389b77f94a816ac45bf1d0ce2b540fd98dafac9828602625088967762f/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string398 = /e377afeb481b30d9979fcbf636df6b5c4f9449b44f6c3d21a768aa5cb8767cb6/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string399 = /e57919a0e3a63705ef452bb2a6bc440f7a6273a8205ed9ce2ccfd063ea9b2215/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string400 = /e61df02bd13c250267ded9f0db8ef0e0f3a3eea63efbb8d041190883b0cee0cb/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string401 = /e67faadd41e6236f2bd67d35c9dfd807ff2941027686632f6f4c339dea8ef263/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string402 = /e73e6a2bc3fc1900fb2810bf53bed0471149fb07c60917027661d9d654c0f6e8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string403 = /ea017c89015802214d1f831d464e018f629856a3a91ac6b350c731aa0e739315/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string404 = /ea30c0eec6a6a2395212dd91016e134bbde0bd99b3547598e1f71b626fe5c9ef/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string405 = /eb8ea449f14a20480c77d6501f8b682516fa4a9394dd15d2a49b6a957aa862a9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string406 = /eb941be4a478faf7f2c61a6d5fb5fca889c7908a0d882a06e61c2e1cefc91260/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string407 = /ec8938be2d1b535eeaf7ba803dae2b6fa1059c6106791d59d98600928dfcc057/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string408 = /ed25f0c61c45c7f013f2f5ef9194cb2854805db9c692f656e2b30a6ad1681436/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string409 = /ee2d0d800b14ac26b8aeae4365df031e0186d23be150308735a0be753ec2d3f9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string410 = /ee8cdc63c2993ce8ab2bf918a56169a815254cd5f5a9a57567a904ec5dbf0145/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string411 = /eeb4247038f58d6b89bd5608782489eeaa7bcfb83d61b5475284ab612978b328/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string412 = /ef44189d246b4a95e0eabbf1d6d86ba94002e6f2bb5eefca8e3e8b8292abc085/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string413 = /efd2156b1477d88b8ce1d9428cdeb1689bd12cefb4b31ca81b70eb7d65e22e59/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string414 = /f0439788bbeda72664259defbc0edb12825cbf2928c922e06103b7b715bae88a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string415 = /f0716ffcfd48207b8de4f82ccf9ba87e876f0700f6699fc1140d08b7a8f741b4/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string416 = /f14655042086ef4653c0351a6464fb7d73473baf26e15a5f59c298bd3df23d1c/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string417 = /f1985ce963979371360df27054ba07df4d4ee35338880bed83ef609a4648c420/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string418 = /f1dc0436b7f9f3f5c5d404cf5fb4a7319ff1cc22a06a687672020af620693f70/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string419 = /f2f9c488451676a58566f6daf2a8a1c85aea193abdc7d7241ef0e12675238bc9/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string420 = /f300f69fe05b47e3b3e571a1fd83c7c0f7d69667d50a78ccbaa551bda3078169/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string421 = /f39f10c0867a52eb9e4d2adf0bfa821993c950feca35437e84d274fba00bc595/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string422 = /f4cb27fb222cdd87a30674270614adfd0aa8350034a8bdbc50fc1967c0f0cb66/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string423 = /f5031cd5e3b444296ef19016555560b69b8f9b54defbbd7e8202b9ef86510d4b/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string424 = /f56461c7a75839fa5ab3f8be2988f9f5d57c8121c4d7c31e17d2d3a7447d2a7d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string425 = /f5acd6dd3812f30ed6a2a2a864231563a962d4ff09c64d21be106db6f8806af8/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string426 = /f5c9543b4b7731b40ea5cb0ebbc655d631adc7f2eedcea1f913e3d4d96b51b44/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string427 = /f644cc4d5e23d896721d1eb59057a5b42d57676ffd7c81bd67b9c33d7db3e4f2/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string428 = /f64a03af886034ad8380631ef1d65728175f5af79674af39c29978a86c181c7a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string429 = /f6b96c46d8395d08ae91d5a19d55f8c9f19d512207612a89ca4c79df0c2f3c5d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string430 = /f8b9c30d3cef82aebdf5dfce8ba7d6a4943a4b51ef64223b59c5241e3023d8e5/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string431 = /f9c6ad68a9e3903d1689cd85e84f00aa892a9e98b368a9f062599da9d2cb4967/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string432 = /fatedier\/frp/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string433 = /fc465df713f8c9d63c9380aa9da72b6ef639fb44917aed390d9c4d08c475a20d/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string434 = /fc5c5c5ff93300cea3141ff55fbccccb07cd0017d4e9cd4bcd324563f88f53fd/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string435 = /fdbcc2a7d73552e690bc9ca7fccb69b9efdf10fc4d78f0f7c63b14a9129bb116/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string436 = /fdc0bca8460360346991a0f13e25233c87805bdc0f055f221f9c57c33b3b60fa/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string437 = /fdde1a3e82d043cdca44b13c45e7593b61707385b30e919c38615d02d53e4b36/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string438 = /fe1eaa0c7066ad45a8a13838d15a6a6535e69250ecc3ed8c48bfb480c8b87e5a/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string439 = /ff71979ea17d481194beba325a55f5d2a319175ebc6a80df535a202a43614f24/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string440 = /ffa8edd59c275f6c592835b11b1f00e7c83c7d1e91aa8d9f6d666d286e902017/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string441 = /fff687bfe2b84105d847369852022a26a6101d839cfdb1ecc88a45d1683a8709/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string442 = /frpc\s\-c\s.{0,1000}frpc\.ini/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string443 = /frpc\sreload\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string444 = /frpc\sstatus\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string445 = /frpc\sverify\s\-c\s/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string446 = /frpc_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string447 = /frpc_windows_arm64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string448 = /frps\s\-c\s.{0,1000}frps\.toml/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string449 = /frps_windows_amd64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string450 = /frps_windows_arm64\.exe/ nocase ascii wide
        // Description: A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet.
        // Reference: https://github.com/fatedier/frp
        $string451 = /ssh\s\-o\s\'proxycommand\ssocat\s\-\s/ nocase ascii wide

    condition:
        any of them
}
