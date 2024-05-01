rule rathole
{
    meta:
        description = "Detection patterns for the tool 'rathole' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rathole"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string1 = /\srathole\.exe/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string2 = /\/frpc\-mem\.log/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string3 = /\/frps\-mem\.log/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string4 = /\/rathole\.exe/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string5 = /\/rathole\.git/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string6 = /\/rathole\/src\// nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string7 = /\/rathole\-aarch64\-/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string8 = /\/rathole\-arm/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string9 = /\/rathole\-main\// nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string10 = /\/rathole\-mipsel\-/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string11 = /\/rathole\-x86_64/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string12 = /\\rathole\.exe/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string13 = /\\rathole\\src\\/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string14 = /\\rathole\-aarch64\-/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string15 = /\\rathole\-arm/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string16 = /\\rathole\-main\\/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string17 = /\\rathole\-mips\-/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string18 = /\\rathole\-x86_64/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string19 = /\|\svegeta\sattack\s\-duration\s10s\s\>\s\/dev\/null/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string20 = /\|\svegeta\sattack\s\-rate\s/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string21 = /0059214c35241df34371e16ec368ef02023ca321cbdc8608c36ab75c4b14cab4/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string22 = /016d82ec6cf3550ac4dea3881c248a0d544f09144881557439aa6e4b0f134989/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string23 = /024db78c74b32524c54cc8617d1c7dbcd742b0d99bf44087ad85c2e913ca4156/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string24 = /0581143b11d99500ea1fd4b61775c395276fd3ec2a0352cf3b9050274ddd8068/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string25 = /05da4e917b0c66df49df25e8e1139d57a8bfd6454ecd3e69ebb433fe0a52988c/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string26 = /065886fd1e058334a56aae3730a9291f35cc144a858a0435d17773f85b3fb5c9/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string27 = /075860a08ea0a48a076989f101341a2b20f62e493fc045e9b3f2c6b04fee7374/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string28 = /082b4796f2b2fb7a81f9f00a8b2008713fba88eb8d80266c12a24a8ed3379101/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string29 = /0aef9a7896fe8bcad991aec5afc995529bd676169494759b4c5b0d4867431da0/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string30 = /0e7eb9d663478b8e6567d14c86a08b41e179a6ff7af69f44d343a05aa5082c23/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string31 = /0efb7bcf56f438180692206231d7119baf1696a927a64097ff0e4fdeb2d7b68a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string32 = /0f37caadfbf7eb1c8d7462487deec3080ca824c06ab1cef3a17ee803f80e0b96/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string33 = /10667fa9b2ff274ad3ad30e8747278bf55a1ff2b47db7fe43216e5f77c15ed3d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string34 = /113d243a2931e1b1b610181229a9e52d3ebd47fde7b5c2f286b8d54aed09efba/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string35 = /113f78974c687c8bc7ba3ae62843a9fdb1d767c85fbbda7779e7199b5a560100/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string36 = /137fc29ed639a8b44b3056598d1c85505650b5ad3a4a4e392b084ee7345e58b7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string37 = /14e7065f629b384425308287023f0bd181c464ea522109846c2d7db26ad29608/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string38 = /14ebe6f781314c1d68eecca437483e92b621ca69f8859a652d73a94dd0a93018/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string39 = /15b24f9b6d402b8f55a96f9deea8cc387513c040030428d9c32dbfb1013d912f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string40 = /167a5fd6a1435ef23452aabcc251924144c04fb75cba9d178d3b4eec0a0b89d6/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string41 = /189b30810273723068cc1de34f0898f999fb1e8e912140e78119f588de4c613b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string42 = /191768fc581508bcc3426c4ed5d227ff4b075d6d1d5309d220d144486d8490d1/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string43 = /193051af6c427627482ae2318feff8615ce834f3c00cb61d7a12e71bfabc60f3/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string44 = /197893f2048f9925f1e6ed4e292ac9e7fc5923fa06cb27f994d26572e8015263/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string45 = /1a451fd4ea04c5e764361e14cf2458ed4c3880659d0aa664c9dbc5ab74d7b44e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string46 = /1a7124d26b8e5b879fd245cd8c0d0eae962a3aa7e897d7cecf23c38528a3f58c/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string47 = /1b501cd229b855a0d7c4fe904c512ea453a3c1b225f55f03a4577e91cc434aaf/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string48 = /1c4cd487862b68af1e3319e7f37e3b37db822b41e580528653c16264e5d44c40/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string49 = /1c722fc7d3e234e27029f791232f8f19460b02226f80d391ab8f2102b5f76c29/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string50 = /1d55ef3e801a86435e2146f3409669fd31cb572500f3da333109f017181114c5/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string51 = /1df13a2ce963c124cb494c745e67d8bf8abb87b94a9b640e5143b16138cb5d2d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string52 = /1e8312b30e0290161f6304f3fe76b7bf1cd111038b09e423f3d30ce1e77a7bdc/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string53 = /21fc8fb357996e9e95c04088f5fdc06cf2862bb7cb074e0f2919e9ed015ee884/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string54 = /22eb2e3f446e71d111afbe7e10ec82d0c729545e7823d9ca860f3a65754cc200/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string55 = /24f8d15c5c09600a2138153f68eebed5831b31d90ae785bf4d25c6129afe2be5/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string56 = /261dc25293f04e40a09a24fd1e039041aea5e27afa7ddb234db3882b74b396ca/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string57 = /262a3f517a064466994ff41b9fa24f03b5df660adf9a4ff53ad34fd071bd85a9/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string58 = /26600cf2666c1482269a4844910e9af915894981dedd319dfa47e7f3240dba7e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string59 = /272c46ee6c8dc5d08397a2d602e398ca5465bce04df1571fc53ee993ea58d95f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string60 = /2874343d4ca8de15f5a994dbf330d7497cc6798e5685db1d3c4a64ed160dffd2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string61 = /28b4073db264ae8edbbc66194419ba03950a22c63c88555978a6d4747245c9e8/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string62 = /2a7a2455eaa1b1bf0ae58b1edd93acc514b4f985ec57c681e85d7490e50402f9/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string63 = /2abf5f64cce68069617766e7d6c105b71215fc936574e31c13a8aa116c14ac4e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string64 = /2b33ead1b58d9e5254447cef54119027e5b1ca360c88e5929bff19685955d668/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string65 = /2b3f74062d1303d71cd368b1090436d1aeddecf45e8561bd94f9fe412dd1abff/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string66 = /2b4df7d7756102aadcdeda533e9372a45ede141300ef3d7941dd0d445de8adb6/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string67 = /2da2aa0a3d231a0b7aee9d0bbd71e6c20a836def31a42711875acc0eeee75635/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string68 = /2e90b0aeb75f7fc93b683697981df8cbcc207690fc550f0d36d80d2281ce4d14/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string69 = /2f3b4900a63d32a14e1578b2de68f78daad89b7c47b9388c26d922962faef430/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string70 = /2f747edb8eed5af60f18975abb44746e3986e332b6099764f91b6e2882736150/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string71 = /30338174d43234b97ffa081de00dc8364df7e1bc50e69ebba7c915c61adfacf1/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string72 = /308128ad3679e15f7992bcb3305e5a286a8a865df3ee7e6b3e4a07b5a041a46a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string73 = /335ce7cb470142a3022d1158a8f102bcd97a8a0348d47022c4674d70a1487e6e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string74 = /336cc961fe07dfb37fc61a5b585ae5b9e966389062aa2cc0d70d282e56edf32f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string75 = /348064a4a5a249c2e4a76251dea47477f366babc23bb26633923c75302d844f2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string76 = /357374d483045884038aa500fdba371af79e095d8e900f2d49bc23c45348ac07/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string77 = /37bc6496577a618cfba0ea53759dabf7e01e218ede999d5290d32040cd219eba/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string78 = /38c02b41d5db41d58683737cb04191cdfd3b61f41d31dc14b8d68a3a141cc647/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string79 = /391fd08daf4986afda1690225e4d9fed0c6d36ad1a56e4362cd8f2797e2ac93a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string80 = /39433eab5c47e1153d8e17086402f2848b7ba868df213fce01db52a664f53d64/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string81 = /3a4ce767d5ff5706372f654aa5ccf01bf84d10dc87777094be635dca8869ed39/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string82 = /3b96ccd1383bbd60d1b79867f5ed32bd15778b94399fb891c3172ea02516ccb1/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string83 = /3bbd5d43f581b39aa84a88d801f48506ab3105b7f958ea718556b4faa4564c0f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string84 = /3dc341f1a1daa80084699b292d0493012a3a85a5cbc157f6984c04def0d2dce7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string85 = /3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string86 = /3f04e968871c818880aa23cecc9239651b7e550a625d655236690af22ea2bbdc/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string87 = /3fad6d60c83b9bce3ca61da5ef4cd799d91e6c1f17db783ebd515953c392cd4a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string88 = /40fa588b18db010c3b2826ea38be66a2894f95e284682caf14bc8894b16c4cae/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string89 = /427b5beef3af730379ab66c28fe12f192768f4aebcd24e02f540feee952d001f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string90 = /42850266bcac0528664c59738c32ba234582c70ffa0326b35c79612914961740/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string91 = /43486a6363b656d155d759db8a67e2e7264c38984c9ffa2d7449dfb085ad009d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string92 = /45f654720ebb2583ea767c849f3ac197e386c6a8dd0015db4084603da6c9ae8b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string93 = /46813eb8d4d50118f67087792670db2b8efdef414c6d3134ad474f1e6856c704/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string94 = /4684afc644880a2ba1b92c512ed3d4e5c653236d370e069b13065b1af878fe5c/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string95 = /469b789cfedcb5d0c3ffd47a4fb4666f38e582b56fb75efb21e38de4b23d8e9b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string96 = /46c6e992b3552d3672c40e7a91ecfb6f9b4620199cf2b5d1dd11cfccd44fa4b0/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string97 = /4721c0b58d6421bff09d13ade097f71af24d0752c2a9d69021f53e2726c76b5b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string98 = /482e5f220835c0ed0bad7c5823a7aab0e3c04fbe020d13f403400ddb368ab705/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string99 = /48a3b1707d22b65890d7feae45f45dff52faa7234ea5fb6f8c738eb0ad265246/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string100 = /48c45f037e2d32fa7f55d0c1e9957bba8cf9bce467437c389c5630d00dd46e10/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string101 = /4babb86918876772a6370e0e08a2640186971a1124728616289a9bda68ddc434/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string102 = /4be299e6a3466a6306d4ead72959aafa4a6c05618ddabc47d67dd0efd34281d7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string103 = /4bf8d88abad30daff8751a1c3a82769901969db2691ba8047cca09641410fca3/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string104 = /4fb15611c3facf046b2f52178d939e5c7b9fbba79320bd0329e129c4f179cd3d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string105 = /5041dad585a35ab841cf44028ee5318b61ce73b97f2ff90757a8ce609e620a63/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string106 = /507fb6f358381291fe987336263b35ab8c49b42abfa44f4b3f159b92ac54c521/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string107 = /51fffad6f5e6f4a431c08cc28c25297e62f85f97dca246fecb6f3c5d3ca22cbb/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string108 = /5252ae734d3bc191efdb95074830509a7ae4293fa25ce866b9fe35c455e61058/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string109 = /53afadaca917c0192ff3c2bae061516c6b14e6befe1d2d5c0cbb5f96de2eb74b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string110 = /5852511a70f384dcf32e29b3ec2f3d10d2704fdaae504d07d3876a887ca05cf4/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string111 = /589f0861ae990113c24fed3527dc6b15d3b9108bfbda358ed10503800820508a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string112 = /58cea3ee018d8f72239d639b012df07d9b0d22e49ecbe2522461db439643fb11/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string113 = /58edc63c43a77b5d217b081b9597824ff4831de52ce2491bcff4c62ce6888e2f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string114 = /5a7cd4fcf7cecb7d346af8e28b49ad66c43d5bb34610485dde2210cadba3d8c2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string115 = /5b3ae3dde66a377dec786323215a45d10f55ada626d29a2890d2f4915111b7a7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string116 = /5b65d6f452aacc65b9282a842c5c327bf27bb92c11d73ed5466ba29f582bea07/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string117 = /5c470be4bbc5ffc24dfbde00aba320a8eb66a4bd2889a02e4e97a5c12117e061/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string118 = /5f9832e49d35fa40dd007cdb3cdddfea38ea63079cce124a01b43d7b47d4c6be/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string119 = /6130adcd3415141a87525d6a511d996d1b17afd3f9876e48b36f866c86a9f7c6/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string120 = /6133e8d04f789d3810b1c9fe24b0454ee821d809bae82e26642baa6f7a5312b6/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string121 = /62fe7d29d8b013efa5b599313a50713b285473514819ed4b427d910211c53d24/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string122 = /661ff1a84f0413f062b672be7ffccad36357290c76646715887689e3524e2b48/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string123 = /6680fa302838dad7262ebe0dc33c2f954d74552021062e3dc1f20993038e54bc/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string124 = /669d5f76c3456565a231a907aee6c2887a8835638a023cbded6c7bdaa306fbe5/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string125 = /68c3320fc6aac048a90bbbbe7e066df33a9ad43831fe27101130627e1180565d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string126 = /68d84e43220ca8a2245f37422e8499710529197cfa599ee2174049c83fd68898/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string127 = /6988f41ce97bebcfae509ed20ba95dc1a7148dcafdfb7c58452088d6d6d74df4/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string128 = /6b994027ecb764471cdcf3d547532203e4fcbe55fd68ad04a5f9881b56fce399/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string129 = /6c511d6c053f8958c718d4374289b25457d4d426c0215c5eba3616f77c6f65bb/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string130 = /6c8386af326a7123f12bff56f737a825e52564e9f142862cbd88653fc5b841b7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string131 = /6d01bb9b786da4013f55f0fe29dfb7490cede245414db1bac43fb204aad2c97c/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string132 = /6d686399731d32af0783b096717c5a14fdbe74e1e432ee2e8fdaace36ebbbe3d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string133 = /6e2966ff6488fa05ed5ffb24ae5dde4fe1954b3006aa0269510ac9feaf099c78/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string134 = /6e8b78647d756a84e7662d42955224fe17bcea674ff125ba1e63b0737ceaebe1/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string135 = /701fd0ae9d88d3a08c418e9d0fca6651c058b7eef8fb34194acf753bfd80e221/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string136 = /711795b31d4482d7f7ce181b00db2ce2a33d3d7675f1d9feab0e984b017d2178/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string137 = /726996a84c8ef0f3c50ecbab6842c5679c38f73f2dd7d0c7f7b4dec5411daee3/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string138 = /735a96908571fa623b9d4065a3061deaa897e5140724fc3dcb620bdd6679b516/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string139 = /73793e0d320ba7c4a8a4c5b7fe75283ca880530e18c76f3fc02180603301a34b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string140 = /768789bf3298d6ebcd03995ad1a0af4de83af5d894030c67e70edc229f61bd75/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string141 = /77bbb9dfeb00b721fdd4e6bf429487460843ca308673fb344c8ccbdb2e7ee7b6/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string142 = /7836f34128ee338249e00a47199408d57a052bd5f3e542ee9f09b6e42ad0895f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string143 = /7e479c191b5a4dc29c0da009c7165ed6cba9171338a6360ce9e8e83167dcba99/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string144 = /7f476454dbd7fb672b1d63e0786e2e2755a1fbfc3be04ab4f5bec8f23132a631/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string145 = /7fd3bda1079e0e7ca9186f8e2ac6a41c688b5ad0293b9afbe1f4397aa8f26e53/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string146 = /7ff5da235f8932a5e66bcf40bdf79947ebe731f8802af62a10684fed4e4e0388/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string147 = /822374f306a334c37c055f40f4adcc6ef5b381a0e38133760634bdcd480186aa/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string148 = /831296851f3b9f90c613b245ea3957e926f44f8373121a29b3f63df905b614c4/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string149 = /84002e45f5979c6ca1478be38d0215007f8208edb2b4a45e2571f6c003828dbc/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string150 = /846318dda27ff847acc25676c4d7a133ee8ea2cb80d4f5d273ef0945f211dd57/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string151 = /84c868b63bcfba344a52d0f53c63beaaf5dfc08f0ead2cee80656b48fa1d5e47/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string152 = /85549f76ecf192f4e61cdcbedc8af83b48a76d78924ab9c09eaeb31141944770/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string153 = /85bf085697ae96895b2ddf719c382e1647b4f17f4f4dc216dd89da79783dcd87/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string154 = /894368f2b42eac9feee89560aa890c1215883b716232c66f20bf4145d6bbf671/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string155 = /8a1ad5d4fc59693ea546bc7d9dfb9881cf33e48070907a5d7ca1b3643fb42590/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string156 = /8b4cda04c1c75474ce2c59d9acbc32f83deaa0a0b6ce16aff15948ebddfec63e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string157 = /8d2d38ec00ce9c7b59d7fb058a05709c6ecf7628cf9fcfc560c475691badc533/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string158 = /8d800107c780c3f726b3768f5db0daa1a6d3d7ae0a505a8ea93fe554a4749294/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string159 = /8f722963b5b107b2856cb4169ed16aaf5b823df9795bf4dd11b97d644fa39347/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string160 = /8fc95d849e66592d8a52f98f28c2d7443b8b2057fc6bafe2a5fca05251507300/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string161 = /90f66748d7cafe4e995a0ebcb7e7e10b84454618f02cc9dfdcb0bdfa01000642/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string162 = /921cf5b205e08c55b7d72439f0f27c4436cad9624493adedaec15a0283608d37/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string163 = /921e9e63dabdae842d71d8f7e856d50e0bb25fa9e4e8aa40ac248b88fb4cb808/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string164 = /92cc3feb57149c0b4dba7ec198dbda26c4831cde0a7c74a7d9f51e0002f65ead/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string165 = /933c42cc2516eb49b1af6e7a601b79e3e993c192ed3c50b7a96d22398197dc96/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string166 = /95663244ae0b98220f0e0075980c0da70094a06638fb4498515857e92e3f8b56/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string167 = /95f005945eac00f3412ffc59d7c6bdfce751fcaac307f4b599ae917e98841766/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string168 = /9a49111f3b3fcd8f1f7c1ecfe79c3d10dc6ba4e7595e0bc776fb328f70f68705/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string169 = /9c3286d0cb644bc2ffdff9dacb89b6d1b87dabbde373a52e45b73717fcc97664/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string170 = /9d6d883e78e055575e91b222042d50bb7a9d9e4f046257bc7c38e7f57deb552e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string171 = /9f1df2f4b8d5719321755917aa858e159ead67978a568196bde136759e9dcb2b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string172 = /a0038697d35fbe64f1d9edc3493da99bdd0f27f7a79502134605c3064b2c704e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string173 = /a131448308aacfd65d51f1a3861ccee0fd68640ed2694421871d46cd1216367b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string174 = /a2a82a2374bd7e6ade1645b0460c385b124bc7cce906c736f0b067ab21f0edaf/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string175 = /a355fed40b126e5a6fe1963d63bb12397f6fd5a88f0e67a4325dafa925229e56/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string176 = /a3ac47f75e01e2efedea26ee4cf9ef3b4f45d12c45dd429438e03224c055832c/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string177 = /a4b0f3f35a5fb57515736985a37f348b9a3303515d5c381ecf95f3422f124da5/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string178 = /a581c3c813327c36e97ca933d0169224d82a428b596b1d64492b06108ac4b97d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string179 = /a6d0d66175c5968762fcb0cb5b967cb7add0ca4b11fa276899cf8de9a1c20c7f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string180 = /a6d80ede0043ee980ff8f7f70acabb0e318c18d4514f90a131250232b33f2933/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string181 = /a73d83dd80d910135838437fc31497f5a865c8021c38cebe29805c237115a995/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string182 = /a7c2394f127db053d7da7e57353e017b319406f6474ff0318a8545c85cf55d80/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string183 = /a8392f36da158c474403c3fee97076c704714db05735b0c23bec268d591e27b2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string184 = /aafc9e58277f79e98ea146c55da484c7524d7e56b13cb189102e8438f510edbb/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string185 = /ace8104c5e20d3ff08efbb7ccc7a17421fa620ad0130a2f96642d38bcbf2de45/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string186 = /ad1cdabfb431402a99e40c0a9d932fe2153d8a26dc3be0e3a0a3a6736989b2d4/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string187 = /ad62f18dcc34d56d48931cf7559bcb64e46e71feaf7e62ba8608ed38fc115937/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string188 = /ae33a0a1e4918c394acfd08d99853492fc97b9abafb4257fa739b6876a807950/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string189 = /aec887efef96f1f2ef41197b37806768476df4319c5f9a9cccac582e44f9893d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string190 = /aedb3bc27109fe131c2e5fcd778b9f30b864ac438f9252266492ba83ae0b73f8/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string191 = /b084b50bb95806e54bd010fa7e2663adfae267d4baea1b590b8f97a66ae730f9/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string192 = /b14b44b9a2346327ab1debd3d56028c3f861821666cbddb6c084e72ded0cb662/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string193 = /b4ae7e04d503aacbe2bcaf751c159d258fb4f199ccb3b5c2e0587531af6d3c4f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string194 = /b5bed9e86f1fcce890d35bf0f75dcdabe99dece7a1b5af2f1cafb1af5104ec66/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string195 = /b60aca868ccb04dd0116edeae8430c93be5dda4410f766d137d22dc02f9dce6e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string196 = /b6bb35e5bb724ced8d8d7da596f060ec650909eba12e38b5c40bcf32ed5e0ac2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string197 = /b76e232b8d3bb64d981b3a90fc81d1cf4e737fe28dfcfb41e37054a48ed326c2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string198 = /bb57a815d8a4aae884fe930b7a0daa6c408b60d932286fd060a4cf61ee79e01a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string199 = /bc375342f9360b0b5cbcb5a3701c301eaf577ec8ab5d1796cf10908d315edf72/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string200 = /bc4447977cdc9a765c2d6b61aada0fa40f45435aa68b193729cf4e7d8a94e891/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string201 = /bc680f0aa5ee457d60cb9d660071b3bb393f31c05c0e7fd7b89b39584ba25619/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string202 = /bd158af8aa25d8f7123030620494c3296b96e56a1cc387bdf2274635335be867/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string203 = /bd7eb45070c8a4e1595e9daaf55bfc331e5ada1244c4ed496b89225e22429cf7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string204 = /bef64b382548fdcd24b4736f6a92c5c68e5b8555c897ed27d83ecf50f8117486/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string205 = /c0386231b4e1b594981b572cd9859cde3f7fadd74729ef51107cd65999aa8f9e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string206 = /c1e6d0a41a0af8589303ab6940937d9183b344a62283ff6033a17e82c357ce17/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string207 = /c1fcfdac8ef03a170f6ec0f7baa30a470c61585c6e78a59cd73e6d50c9e6f5f9/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string208 = /c3d9753c93a5a4f6fdfd7c5146ffcb2ae4b733926b0ae3fff899d3b0851e0f60/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string209 = /c45bff01783f3f79df4d0c43b404ab3293e4e351fa760d7c9500200d5771d73a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string210 = /c518a96dc78f8a6fb2ccecb02c5ab09bb41f0e04c8f7e7de8b87b3392d3083d7/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string211 = /c5fb70cf2c8a3681d7e8397c8ac82c119f5bd64055dd47432c5e5672ce9a3986/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string212 = /c793af04a5ffa53c8dcde8f9453b312e40168de4081d64cbead076b8e7fcb0b9/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string213 = /c80c697470033dcb0c21c4c8bfb51f8514b4bfc10f3cc64e0960ed62420eb14f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string214 = /c8ca4efbee070fbf92d8029eb0ab7b6debc91c4f7fc3fe6c578c416294807565/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string215 = /c9404d48d63246380ae88630c327b603c5795542b4cc51287bea22a04bca46b5/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string216 = /c9673c278cbf55574c7a8d0c4e067e2d39b938d673b0d7332f58d28170ce267b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string217 = /ca6c79f236c29b8a923703800c1bc63ed8eb9d4e7f1951e9660bfdcc2b98e55e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string218 = /cabd08e92a016eb971ebda7ee0954f8e2b9cc234a3a61e4c04ce6fa97798ff06/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string219 = /cb548fc5c8a0eccd0a51a371d5ceb8abf994ea20a570d97cbd4592db6ac1919b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string220 = /ccfae00ec39b5da0ecd9b68049725f07ac4a340c837fd43468419a5a5929f103/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string221 = /ce30c574477d0b2527ccfe103b31d810f6c1aa8a83c08bfb5899214951d75c0d/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string222 = /ce9c03462b055ad6152b572662fbbc1febb19f9ce41f6ff7c7a2bfed51102166/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string223 = /d00b56fb9a39f27ad1c1b95a397861ab2d9898e13f60046669c72b875dcd43f4/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string224 = /d258f53b9e011e64920fb4f74c2cf0386993b9427de52c71b2147676422da83e/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string225 = /d5f0bd19109ae3e6385b613848cc09bee2d9b9a853c56ee82b75c888a2369499/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string226 = /dcb2717dd9c64e62a47b08565d50d43f8be857b9febd6f3a150941f95ce7ba44/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string227 = /dd4a876937f29c0732fe28b12d83372eab31a776a0a5c59f774190163bc6d442/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string228 = /dda6b391a168711d19c4499aba12c914e222dd053def0c21d054d66c53226bcc/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string229 = /e11c8f5673861b72e624373d2ebfed1cc50ebd59c8633da4b87a1e2361a53c02/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string230 = /e16e725b1a703f35d47a43e9c74996017703a65bcfd2fe042af15185ac856e29/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string231 = /e415807ec90293945012e78bfc528d3585e7672ca050cd3b56084e112c2d0249/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string232 = /e51c2e66cc4407d842afa1c1f700549da5efd37a6bd2dcc5c8094b777c72bc76/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string233 = /e54a93d0138fae68b4876b8f9ba5f88d2ce5b0d238a7fca6925ad6d0aeac5d98/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string234 = /e66e1d2a59507e235e6302d1a00e7bb3df833ba25b7151ef2d7521dbc1c2e3f3/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string235 = /e674a3b1a74f65ff587eef1080d3ce789484615f66af8c9c332231e9304f5220/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string236 = /e6a85ade86d4ae629e14eecf8883a618a8ddfd4c02bedc77cbb1a9e3219a56f0/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string237 = /e8662d80d2cc9acc5f8f4d8a1c1a5ff7717b2fa71919a405d0eed8b64c8c1d88/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string238 = /eb23b507e63729581b16b35de2db0cad23cce0afc1de1018198066c20e5c0c20/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string239 = /ec79b650c290fdfc46a1c80359337ba7458eee334197d2aecac4a3b86db1a1ed/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string240 = /ece4f9a9ae3d7823ed86c3dcc5540b02c7504904bbe0878d17cd7bbf71ac61ee/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string241 = /ee5d276260040e43272cdf7c70c51e4a03a959e0bd4f3f4752edb02569c7736a/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string242 = /f052586d3c8b6cecbafff4773c2a67a130c00ecdece4ea43f101923c53c28f58/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string243 = /f160f0e2319e8ead547548ccecdff561aea5b77a3bb00b387e1ddf3f1c3298db/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string244 = /f1c1f6e3dd1697be115ea8567fbed5f993832bc5e2400e69dbac6ccd95d02c61/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string245 = /f36b371ac6f48895384d78dc53d83daaf59d6f7086d5cb9ce7c74ba60ab81a0b/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string246 = /f415f14b5c1f88971cfd80555ba1a0c77a437401a7bd623a616261b7985ac5c2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string247 = /f43398d585caae28761b340c083216b2dda0898667161c5a43f587cea8b7f799/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string248 = /f4a0d07aa0dd0cb020a0d3273a615107ddb15ca8264577ac4c22e41cad47a2c2/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string249 = /f57034e42cba38366cfc0a304f16b1c1412419e322560d589d6b896312acde7f/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string250 = /f889e16f7550565628be5da507bbf33ab1fca61ab3541015fbb7a120a3a9cc29/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string251 = /f9b0e8b9bdc130652b4ec4c86a9c2d03dc85bd2057401970ff34cb5284581b90/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string252 = /fa4a6fc63d86f8f1faa7c103a845e4715ce79a048455c0eec897b27237576564/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string253 = /Failed\sto\srun\sthe\spingpong\sserver\sfor\stesting\:\s/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string254 = /fb75480462e81fe6c0d821641057d0534989a45452feb66851bf781e42e82ef5/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string255 = /fc3b41639946509efb1f6835bc2da2233482f71859031aeb73006967ef5d7b66/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string256 = /fc6b0a57727383a1491591f8e9ee76b1e0e25ecf7c2736b803d8f4411f651a15/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string257 = /fd243d10718135287eb1a555427abf58fdf9cabad14d08d31815763479b877dd/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string258 = /fe24df06821a78f1ccc81a8459ed13a14558b632908b266864257636e4fa8812/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string259 = /fee22f170cba77a8a17614c87621393e45ca2d703c049ca5e352083f0c9dd313/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string260 = /fef39ed9d25e944711e2a27d5a9c812163ab184bf3f703827fca6bbf54504fbf/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string261 = /rapiz1\/rathole/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string262 = /rathole\sconfig\.toml/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string263 = /rathole\sserver\.toml/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string264 = /ratholec\-mem\.log/ nocase ascii wide
        // Description:  expose the service on the device behind the NAT to the Internet, via a server with a public IP.
        // Reference: https://github.com/rapiz1/rathole
        $string265 = /ratholes\-mem\.log/ nocase ascii wide

    condition:
        any of them
}
