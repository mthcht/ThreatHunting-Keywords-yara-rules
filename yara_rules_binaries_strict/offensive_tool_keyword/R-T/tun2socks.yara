rule tun2socks
{
    meta:
        description = "Detection patterns for the tool 'tun2socks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tun2socks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string1 = /\stun2socks\-darwin/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string2 = /\stun2socks\-freebsd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string3 = /\stun2socks\-linux/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string4 = /\stun2socks\-openbsd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string5 = /\stun2socks\-windows/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string6 = /\/tun2socks\.git/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string7 = /\/tun2socks\// nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string8 = /\/tun2socks\-darwin/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string9 = /\/tun2socks\-freebsd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string10 = /\/tun2socks\-linux/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string11 = /\/tun2socks\-openbsd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string12 = /\/tun2socks\-windows/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string13 = /\\tun2socks\./ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string14 = /\\tun2socks\-main/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string15 = /\\tun2socks\-windows/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string16 = /000f59e092127362057a472411b5395360cfbff686077e7741fd03ea22e12516/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string17 = /005b0d233056c44a7c6a57a078d00bc23b07d0f643a23ead7267be2d11a23f2a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string18 = /00edd865b583264ec504752b1a3c233313808b9d531a0f850998fe01a9522de2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string19 = /01723b5e0bb24057800417322796141865b8a5883c079ccd78dc0ffa9a3c496e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string20 = /0186e7cb9cdc480d638db0c7c7ec42ce4b538e930a416b889cc3aed7d3938bbe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string21 = /01eaa83c281f96c0669d3b898bb6ea2a89d00191eed047bd7db9527115ad1290/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string22 = /02551940f2ee1ddd51aac5de97a84b5ce7a9fbec1be8f2c5018b2f7e09f7e1e9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string23 = /025c793845527566066af18172b76c87b234ad7306040cdf734ec516a6afda1c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string24 = /02b25adcd66eb449917f1d59d0c0f802baec912f2f98293f0612e30b95927591/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string25 = /038fd0cd088e5688b206727b5aa52711a21b929d76a6632b1996af026864790b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string26 = /03f317c41d6a2faf7eb0a68efe112f5d8bf30df57d16a9ebcd967ed57ff9fb2a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string27 = /04023f186dcd5a760dd8b41831a234c1e7729fc4a1b5e43917dd8fcb139d1f65/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string28 = /0604bfcb72cf0604f64b66202027bf2cb5eca29ffa6cbf5fb1fe8646bd1551ef/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string29 = /065d34b6e01e8b1f150971ba0a3c565372ea2af62314e18215f062ffa2625335/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string30 = /06c71bc30e557ceab6964543bd0d68e1b9dfefa272b51a46f60171af621b5f42/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string31 = /06c7708610ab5a1cfda659fd349fd92315a4a58ed851466ce565e7866d77f375/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string32 = /0704e26e14a875b68311801b1009c8e9291df4709ff24e1f1aa877ac57b035e7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string33 = /079bb8c94b5877751bc6015b2d82a8721d150a9849482eaa3b6332d252371f72/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string34 = /082d22b44f305420b9ac577066effac3f01db0431671bef3667b6388082683b6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string35 = /089dd9652baa70862d00f465c81a5df3ab7129e82dca73edea36d0cfd8152b89/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string36 = /08eca2f2424877b698312c5aa652d016398dbc0d811326202cddeedfaa8700b5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string37 = /092ac8a6ca4a373a9788724e2b89c69785312fc7d7d10af083a3b480a58178b2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string38 = /097480e794bb20660bd64c5fd4814d9aac0135710b28a85ca643422041773dc6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string39 = /09d13749a026c345f3f75549abbdc3b082fdb3e51f43bd62bbc0cd2dfeb51e62/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string40 = /09ffc42c2a49a422f8092f0cc5c899f92144e667376aa666c36799c70a2d491e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string41 = /0a1b6ab86651abe08734c0f185542c08ad8942e450b822a111553798f2f37302/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string42 = /0a551dde187ba9984902de12b5de1d1d6ed17ba02eabeb9fa41ed2fe35d52faf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string43 = /0a6347197e46688711834531a7f75308298a9aa543c889a61260138d73e96634/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string44 = /0c5c865669aa4b9ae6687ff50eb22888b0c3afcf6a7cfdfc63a2a2dea3c6d9f5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string45 = /0c96f88dbaccc1386890569356cf4ad5f45bbc49824ee7578dd56fa677460cbd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string46 = /0e2229f85a0dca6457d05a619627075db242eb3fd0080d9a8fe8c102ce5fb71e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string47 = /0ed6cbbe7b625c83c55e0cdb90f138301afc88e23d04e32eed39b078f7c2fa11/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string48 = /0efa187631cbd593e757b52c3a2e8328857b1cd15a93724870d767f71964dd62/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string49 = /0fc82ac081b6c592d5e6fe4ebd650721c7cd19e9810a26927874ff95d073baff/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string50 = /0ff4c1a9377e072a07cf09f94f8cf6ff423e531aab8a131347ecc5f023797eec/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string51 = /106c6250321d09ba9fef27ccd9506234f00e00c23c6b1c7bc0541d42e96bfc25/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string52 = /11350f8f9a6296d6c3d2e74857bd3d81d180134e4cb5320fc42795f6922c1a02/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string53 = /1182b15d8277fa6ea660c74b71599cb2417bdc28c889215514f414978a26a9d3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string54 = /11d8e391f72c4950369727c3bb5071ecb806326d1631556183d7ac403e128d97/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string55 = /136a55413120685e63b3ed8ceb5d3bc962aedaef520aa0d99ef347f7ae336f73/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string56 = /138fe6fe7171a4773027d687cf8b2e845b5e731ca1b239a5adb20cebe4b662ac/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string57 = /13a77d1e3def5647f6d722269566e323c3a22c3793161bfda53cc7434e202b1e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string58 = /13f225c454a7e1468244c9dbaad2e1968034e6aea0e16cb67a5139d798e05fbb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string59 = /14268c474399ba634f0aedcd2411566fe97ceaecd2877cb14980c99bc43af31d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string60 = /15b508d7f36e8f43dd0a0c5f1dc63d120c0cdbe68cd18247d6ca18a9ce6cf807/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string61 = /17837e91e3fcfcf19ee77bc80d556e8bf59b411aede445ba030b0f8d0e264b11/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string62 = /17c49fde584e67f0cde80e74bdf31d3b7bdfdbef16a93ed41aa6fcc593fed2b2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string63 = /18913650346b45f2c32f414f1f82c5a6ca6fefaf7294e292c71cccf18332632b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string64 = /18a3d4ed574aa0dc9739be285b98eca7fc79eba3776821a13539f06447a22704/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string65 = /1a8630762516e988f1ffb834e1e345c44d8b38d59dfba65ebd36d70d67241014/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string66 = /1aca0bdeda834669cd00738ec80f1f092531d1b1d8f7927c05029f0978544035/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string67 = /1b80f6a088f3bfc7f72208fc3ef8a4471e37cc59f4d13c863deac34b51f8692a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string68 = /1c28d23e9c40b7f247de4c2b2976e69a644c901bf2afa5c78366a11de9fe090e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string69 = /1c4b5a0c298af06402c2aec4c90a3b9a3e0fe79067fcbb8ea13f261e9f3b5405/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string70 = /1c4fd2d2f860350700465103ebe246d2e50c1090d9e12872e4418cac765cae20/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string71 = /1c7a0b2c6c4f86ed3665aef0e0482cc6c5f9a9daec792714a4da73d94cd93ffa/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string72 = /1e47114546cda37a3ab03867aca5b78bb1ccaf41356e39d572a3ef398114d361/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string73 = /1eb4e2cd15083c230408677777e1ddb5e31d04ae4b8c2cfdda52dd0e8438aa4d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string74 = /1ec72a3db270fd02e4a94d1bcf92bcf75637d0563d38ca63f296a04c62becec8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string75 = /1f836b4cdd973bf9a2f55082dff78600498c66597496f044dffcac82a332e4f4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string76 = /1f91cc9649031c4c80acf0d1823d439b4d49b89fc7caadf035a3260843ec950a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string77 = /20674c56f95e970818056b474668a43c64db6c414065cd47db9a375128d1cb09/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string78 = /21533d1133ecac5dc01a087b7deea5f594b3609d64e96f8e83c3fe458454722c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string79 = /21567af4f54a515da69211edfabdfda681dd5aa01263c80467394a5c19eee333/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string80 = /2189fb112297e59da398ea1b3e4bfa997d6af054c7b365a1c60864515fc6807e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string81 = /21dc78b6f950f4eae598993c27ff7af3528ae7b7a7bcc8126a691c4c6c65efc5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string82 = /220f7d90df81af2d014e7dc80d6b6705b6b8f1013ca9938076a3bac88f6cae7d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string83 = /2235cb273649d86f24c4d843a9a637b44e528643a73ff9f6013c446df18c430c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string84 = /22c8f466cbb5c2845a9f943374032a476ed03ef4ff0b8398012554e0109e5849/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string85 = /23e478a34911f053cd097f549ab4a75a249cc03e565f9aaf512af6bb44acc61d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string86 = /245f1d201e526f91b4950e1c23328f2ac2b22d6da4d6c56aa63e3b512d980991/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string87 = /24eff9f3b53d50488cf9260a59dfa59afac34b67d6dba4d156127b9a72713088/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string88 = /24f4f092e673651bbd2ddc5a97f8da0cb9d2bbe49db773c691ca5f4251f4d871/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string89 = /25753582733a48c95a3f179afe3d54e65fcec6a7283a94fcd33f18808ddef166/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string90 = /2677ebb8de5a2911a2edf04e2740812d5e4f4d93ddf370685c4f4176963b675e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string91 = /26db7b92f4cc5c522ef48c9d7b41b8d72dd9a02b692dff91ca6234ee9559a5a6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string92 = /277279ef4352ec8709c69d481ac9ef31fb1c07070999e229ce74ef76e57d5f84/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string93 = /27b5e167bc93846e1dd8175a36012073676173be8dc7c951bb4d8ac5fee576e0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string94 = /286ccf98346d4a92af9eada9e364e279de416e110e9f1ba283f78fcb432579a2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string95 = /28cd619fdf0d374589890752fa44f8fa07dbcad9af8603313f6a88c8da2e2274/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string96 = /290aadd32b485a7b190c623da4cf6069e25cb58a0e86231443cea3fde5082532/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string97 = /292ac9fa8bee24377c4576b233b8d56afabe4a667aa7f08432419fef0114ea9c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string98 = /293ad8aff285084f5430efae637fae32ae46e0e72f4a2a80bcfe7da35628cfd7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string99 = /2951bc5d8e2a90fef2f61add1dd98aa688862958edc8501acab5dd0782a52171/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string100 = /2b0a1ea2047bacd811ae1945de0e7a6709565c0ac8f67c01728965b587c27415/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string101 = /2b9c9f74214777f8f564643b376c03b6517edb200bb62c832d17c154123aaca4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string102 = /2c2e002d5b85945c8f2d74211bf936268e37d086c4987c14909ade7fb2460e9a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string103 = /2c3443b8a35d6734ff6a8e6c045bc0c65f134ae0a2937ec8986447113e9a3b98/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string104 = /2c7b76a89a8b9696eefc5144c590804f295ff593c9168c773d0b644c69acef8a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string105 = /2cb57e3d7d12179f6e3388a62b906a138995da22a57e389079df8def186afc00/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string106 = /2e10414ca66fb0469f425572ceb27299306a76d1ed0a1f39050314c1ece46f66/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string107 = /2e635883f111c05144ef8473d7a7a35a9ce1b5d50e0f944957cb39a39c860bde/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string108 = /2ed48bbca6f89e16c2503726e0dfd5cd01a5ec762178a10d598e91a68beec841/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string109 = /2ee7f67057652ae099d25d96acc90bae127af618a0409fc2a603e6382cbfedcd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string110 = /2eec07fa568311a385f0e0b9a26b1244901efe0403163bd79d1247d1b4e38c9d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string111 = /2f48cac314397716defc882e1040bba75ea54507aae551a64f67ce21e7d649c5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string112 = /2f66770e5243fc4bba4b3f8e15a093fb8d433909345033a7481e744ca24a4196/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string113 = /2f9b03c897526749ff4fefbeec1eb89fcc5c303867bcbfa40ed7257c77dd001b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string114 = /2fa193f29d79be4213c7310cb815f08c4c426ba02720d598f79ac0f69fe999ca/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string115 = /2Ftun2socks/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string116 = /30250e5814a1c0735d0f260d69ae237636f795f6a425ad2162d18a758e0fef1f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string117 = /307e2e6e52992a452f593a7a0c3c04753717949c11b0d43fbd47d44ddb6854d4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string118 = /30859c25f2d9763bf4a8416c82d125bb11168e48f0527ee36741977bee0354ac/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string119 = /31c88d5ad49ee789d4905d5555adf6352e22acb5e8dfb62866247af7ac9525b3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string120 = /31da885ad54c3557157849781dcca4056bd8594c5551114f1eb7b43f704692dc/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string121 = /32ca6ae0de534fa368856fdec13bf2f5ca97879f1e50d5b789c5c0dff5081150/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string122 = /32d4ef57fb08b0312045fd5f521a857f42019c4edfd21757bfc2d5dd2d4f0254/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string123 = /32e0f5302e5f96eebb6d3b5c4492521713f4dfe4b377a300a5313533c070b62f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string124 = /3364dd7d78f44251e596a40b35adb6fcc5a38c1da2741f69e13f09cb721dcd47/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string125 = /3606d9525c865d6167a94ed60c9175e90f516104cbfe435aa30a34d05745badc/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string126 = /3608033d0516c29f2465dde62421670ed21b6da4ce9c9803fb09c0debc7bc8f8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string127 = /3637cb58a5fae664a12943bbc979556d11b88b918bf8ab9ab78be4e9d9d3292a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string128 = /366dfaa9fb6cdd168c41aa608cd363c1953aa2126749000847b5a282835eb0a5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string129 = /36980b0616d902fa05508052ae1ea0224a82b442e45d1756e71c0a911456712a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string130 = /372411e7c2512c38573da5590915f7f5bc401d3273e5a6bbbe5c0854d4267458/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string131 = /374cd6159d14dcfe12e51038c9ea6c5e954346963a705f6bd7ab2ce91b37ec61/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string132 = /3843b02a960a6d676a9166a51da80aed18937ea0b582895b6b2780fff58417bd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string133 = /38b56d8415cbf78361f7748a637162c03d430f698862f6a3d4a1d7b450971053/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string134 = /38beeacf86dd8936b862c650818a65a0386a4cbd927c8191e84f9b8c8322a09d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string135 = /3955964e71c4cb56d759d128097b15278c07c9ba0fb280958fe42a36ea84baad/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string136 = /395d96a331abff7678ff53367fc4cc533be001125533a989688c17476d0f0125/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string137 = /3a0c5bd8c15075019d478b01768e3f81adb41a1bda738c8992d5b30903d64018/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string138 = /3a1f300d7497b58a8d8719e6fe6c9f7f3888e501ac601ff68712d96c0c3fa99d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string139 = /3a572dd23436b9711f46a95f68952fda333a12e108a0a5bbded06a0e3c29c382/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string140 = /3a9ed2f23a034826d0ed1ef03f582b92e74cd4122abb9ae8f8243480d1c4411c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string141 = /3ad929cff8321e12459ff5053015cbcae9e4262652210e270077b7a8587e2567/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string142 = /3b16492476a023f26e1c2539fbe209b60f80194e700983d2b3015827cf299e5d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string143 = /3bb722c6626dae00c3f31a30738761b013d0413b0adac000e7a783fe5cfc4613/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string144 = /3bce7350a70402df5ef6e8b12120ec12151bb3d3c6ae0e7b9eb9c1708acc50d6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string145 = /3be874d1451d77eb17c7d8bacd59fd079959385e17068fbb66481e68a7f316ef/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string146 = /3c43abec5368c3917c777012e70ae7977f80f170ff3bd0400b907fad09b8acc1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string147 = /3cef33596211f12ca62d6c531f5e6d31351616888eee9ddc4a315d49660adf56/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string148 = /3d63d98655436fa1bd05ede7afdc60fd2418f18cf64da091a5ae1bf7f1923687/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string149 = /3db74ea470a886d624947d5e8cdc9a5edeba429ddf39b1cf54801b7d5ec53137/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string150 = /3e6e443b0055c7aca76387e9c557976887ecb6bc342185e52d514503b09a535d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string151 = /3ea656dd07b50bb2fde472461341004a231ab56ef2b3e7922910d38ec98d7278/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string152 = /400b16a02c12bc59f8002db251638d4450c5736721904440bd1af274587b197c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string153 = /401e82b43a6ac88e204d178b6ffcb43dc33d13ce40b26739c5302030154469af/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string154 = /4153cb9a9c23f7a72a60f0eaf0a615fe95abe975886f65e80afea2be15aea242/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string155 = /415f579b9741f7936312e0320e2da763f7cd9f29903605f3bf1cfa6f28f791f6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string156 = /426ba2e010fea3c33ca7c28049d4ca4cb5a9ed3657fbdcb5e2749852b7c39002/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string157 = /427fabcb0798815ea87800466f168023502fc0c12a17f45b40c078bac25fbac5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string158 = /42963db39280206317fca8b24f4f10baa9f6b2231cc150ac3c2ef6e4481bdc3c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string159 = /42bca2c91d21644cc8743f9cf6c0ced70d4fb27b3575cde43629633d19bfd718/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string160 = /4326c3679fa4ee537a32a69abbbd19890aec7d108ad19d3a86eb3724213e031c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string161 = /437c338d694eab03b98922ad42d0ad890be0e7c94be0a278115e638e2dad27c0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string162 = /4427e67765107bd7436624619a93336d4ddf0bc22a0ae1a2c8dca47a04d4d2c3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string163 = /4499aeab182ba401920e4177d8f78628d789659bdc5fb185d28eeefb2cac6527/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string164 = /44f2d9077535e735d92db431ad39f369175aba9fd5986d0bacd593693dc9498a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string165 = /4510d8b0d9695f8d29ecc32d96634e68188ea36dbe15cdb26a807c07561ed791/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string166 = /457357c2ae6877a930e6d7e13fab96a5f45465bc8b0d8af41663d31c27943fbe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string167 = /4777595decaa624e3a5c966272392cb58a20add5e7ab25d7a3d89e923a6905a1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string168 = /48c54a40a96fbfbbbd4b6f7c095e1eaa9f3ff33faa096fabb7f5ff04a6af4e5a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string169 = /4909f675efb667170fdc1fb04417a959d2f016eb7aa8fc6a41731788bad91c27/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string170 = /497a4330455b6f5e625f1d9d7dd92f5c93f8258821b4c26abd142813f8873208/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string171 = /49c1d5aafeb8e45567b93e3bdf9b229b467eca67d53f0c05a812a5089f6c46ab/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string172 = /4aa7737009a9f06b9f4957c4fc12932ae0cd2039471d2ae4e5d4666ffeb40a2e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string173 = /4b9bdaff523939442961fd62acfe38c8bd379dd294d066d4770ce15e9c955e9f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string174 = /4cb9f011b700a4e9cad44ca5b8998ae431fcf8ee74f63d343c2504ff6efb1b8e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string175 = /4cd278347df495ec92b7acd31c4c61ef13fd6dd9faab74acb09b2ef4360aac6b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string176 = /4d50500e4170dc1fd2dd377467ad2722fa0db20a0d90407d15e6856175f26fca/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string177 = /4d8017e676ae345fc21e9037d70cf7c8444c945a61a533dc1926453caf7457d9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string178 = /4de62887a3d002ead967d9ba1a18f05d5859429477457b6da2ff54f2fa5ae624/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string179 = /4e025470453cc0b4c72b384b1441ecbeba1cf3b2ae98837ba630aa5102d1b6d0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string180 = /4e0c5d445fc69d7fa6a1e8f72682d16055870a743850d9accd51f2c4cc048000/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string181 = /4e2627bb524a79ae5f2f54a5a209b27a8901d2a92ff466621edb587b504c0428/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string182 = /4e696f42a13a53a3b747b3575fa66b0ca4b71359a932c7b9ef8d4962bcb7f085/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string183 = /4ee43d69320e28910a475259994a33b3725c7b5d65a16a457354d0c23a51c820/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string184 = /4f38ded60a6580dba88d19fb2a49dc8391a49b90133b1daf25a384d5d94111be/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string185 = /4f79abecd004edb56882c1437e180acf8352adf3edeff72546a441f02db30b09/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string186 = /4f9185140867a6bb07dc99ff4f41d8e3e66e60b27161b613887ed8b38f956fb1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string187 = /500fd5f1772e01b5f7832f48e36e698204db2b8944bbe5162b77a70c2c59c044/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string188 = /50588c73e5448ff5254961039e431e5fd4ad532fbc58483c53870b77554c0ad2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string189 = /50cf6bcfb14dc0fd05eb46a5b8a804541879a555c1e50ce64b766af9d486294b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string190 = /51474db254eb9ee763f92372d5056aa268269e60d4b7d83cb340734c1c10ec65/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string191 = /516763824343085c42dd86c02b55fdb57ce007b6f06014172ff8fe4bd8547351/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string192 = /516c132d30d40e8bc6177436077749f29a4862533bb5fa0be81e5d9936b98a04/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string193 = /535d2f13597a9418a665c526c21d8388d0af43f331b2da125ffc74f0b0686cd2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string194 = /53c5ce630848990bacd8fbc314944205c6f9d3428d713cb457190290b0c51769/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string195 = /540967d13db656212627d62d92f1ea985fc668cd5ee0aff670d2ecca51f6d302/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string196 = /54c10f32ffcf38d05a43d06bebe74838cfbad7cd45da199cc5b02e6fc45df57d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string197 = /55adb997fbda60a19f5a9c98d602976d6d30cb7ab1a4c636224e442ff4054ac2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string198 = /55e4a7e082fde26e6fbec0235f5e722e07234e14026d9c18f24a0e126777d8ef/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string199 = /56563020331400f5b1da0963a37a4a5210f4bf969c594f637daee819b98e7ecf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string200 = /5669b6b74c00b6c512606e36325d11ea949f88cb29e35e70d4182f3d1d5b7a04/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string201 = /576908f3dccaced486894a56a256a88dea369d97302e1793f17660f7062d0c22/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string202 = /57cc2a0322016a734d1ff1718bca7f1deb0df3309eeac2222d663b48da7dfc65/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string203 = /580bfa0e4cbe1fd71f578f3daafcd0d869e0bc29adc849e12d0148b8cc016745/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string204 = /5c0e2b1e7facf950cf245eca4c1c5533d9d7bfbeb804d1aa18f304fe1fcf5aed/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string205 = /5c19bc2cac0c45c991371aa4395e31e8ac7104d807cf8d1c2c3ff1f8b5e535f7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string206 = /5c257d91b3148cd1c64613a7e1fb1902ba092a964777f6ea4aac6884b6c2f542/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string207 = /5c35b47cb32378235e9df3c1d9a07700d4c49011532781cda0c0a8fafb4927ec/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string208 = /5cadf4e7a35d191850cb6587b934ab191b781c9465d39bed7b0ae46f173ed43d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string209 = /5d9056bbe4482693b730e587f475256b0e706c3b4a820368f58084aa7d158e25/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string210 = /5dba56860b0d684c8aa7bd7d872e31b87ecf7a98c1c1a696b537d63a402aaf53/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string211 = /5f478850626a5b6b9fb2f8ffcdc4178424f4fc907f7879f1419e35963afb916c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string212 = /5fd40c34131b8d6ea75e04630018ca96f144074e3d471d82c1226fe7356ef194/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string213 = /6009ef1efbb6273b711b329e0a9a7697b2eba2b0538d1a2b1fa160ef30e8d5a8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string214 = /613fb7b9493ff4c81e4d1cd45e819aed16a090b28b76b9e3081af8df09b5941e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string215 = /6165159a8e0b04f13dc7ca465f9553e9c5e0a8e601d922c14a60bdd8bcb27ebf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string216 = /61b9a95658575424bb3e30ed5d83ee9a327924c7fe65d8c6379a86db287b3fea/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string217 = /61f1bf9bb6daa4d45e44e176c22610569cef864f328390b142188b52f9984195/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string218 = /6205ddc22a991d9dba9457361b6d4fde7e51b4ca388fafa89fe883a8969202c0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string219 = /62097f745d283d52458f0b9ed9d792e03a85dd92f73ebbcc39e125a9b0e368bd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string220 = /621b1aa1737a16c3f34b44236e3c16afa0e0fcbef095bb4d11ce21715e8cc83a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string221 = /627d9d2bd4fcbb2b219ad2dc49a25ebc695700cb0fc2f1eacdd56cb71d44e258/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string222 = /62b0e8dc11a981b51b71c3225f8720e33bbe39d65030fa99d1a015c1a1f7c891/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string223 = /62c2a21006b98e0d124c262372b96eb10f15dc140b5cddfd513454795c55c47f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string224 = /6308bf4ba359c23171ea4efc92a5bc51bf3b52f79efc14ea99c5d6454eacc099/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string225 = /63109331510d0f6d9baf8b41017b9187c80f2ff24b426750a1f7f3fe8e82d00e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string226 = /63c0ab8a69d5eaf913b7f348ff7ab6705e8185283d08f455b7f194319ebf7f12/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string227 = /63d84b4b0a5acad4d2bf346c746f60f53e6e14c09ae6d5271cd755a6ebcdcf66/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string228 = /65b60edaca65b2e91c9c8b1006efd29087b58b96adeda130787e77801ccf6682/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string229 = /65d48351ff1feb4d9577b9a8e395ab5c00804d38cf28f10b2386a57047cce489/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string230 = /663792a8eca37f76270dae1ebc24d3c29bd028457478f2b505839f9303818648/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string231 = /66c22a683d5db931524f36f878f343210a43c78b5f09aa2b78ba9511ea76f679/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string232 = /670b7828e25e5f8f015e74468836762e764a4e345d851ed656715eeae70cdbec/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string233 = /674ca493a5e0a62ec5190a54861a065b3b3a15e59fe74e4012590f97329490c0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string234 = /68d8cccac7dcacea5a989ca47bd46f153d368cec93991fa8e3a1c950fec75508/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string235 = /6985cca5e98eaddf1cde30a918ebfa8ebd6be892df518232b3a0b63e29043df2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string236 = /69fae7c67545c79f70861ea4ec8b7244b555fd1898f6966e0698e1d4d4446081/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string237 = /6ab49d8b\-a009\-44e4\-bd53\-fbdb48fbe7eb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string238 = /6b93d86d6d72b894fbcc5f895ccfd701605fe1047398d17c3c6ba1159ad6ee4c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string239 = /6c1ae2e334c3636ebebb7067a21ecd2432d882d49b3f8f740b4e94e8aa64dc8c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string240 = /6c4f7d10004fd5cbe197202612072cab361f1d39df0355b5a2f1d01437316128/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string241 = /6cb434e48f7e61714d422dfd0cb46d1afe621090e1b432d5cf0030856f17d42a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string242 = /6cbe75eb761973426dd29855c69210d047b19883320e6bf912df6edafe4826a9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string243 = /6cbf3184ec914574bd0d30126a34ee7e0d26ddbc7ebb8a6fa1fe294825600a5b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string244 = /6ef0e134f1bf610e27cf4c99c2402bd74d00ea214cb6aa34daf4e99cfa66270a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string245 = /6f27c494cd5373780458b9ed4ccf9bb172f1782e8e2c1dc630793dfe26ea82fe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string246 = /6fce39600a4115976300ac936a140aa10387d0b4268bbd0cba74dd7f8775b844/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string247 = /703eba011f882e07ae16555dbcb5c774ba822c83b2fba1918d4e807549111420/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string248 = /7054d78708ce7b1ac69aec272a9121fedf2ed2ae9d63813dee67a6f0838358f9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string249 = /7055ed92ac04384f9e29339b6f64d5cf2f76dbdcc25feb0772020319675524f3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string250 = /70ad2f1fec1e1e6f270ea4fb6b83889c1b5d1fa1475eaeefce3cced3589962d9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string251 = /711eb4700b1a0609805647b1cd85fe3a3a0122eb17a2bca7488298a27d4d46c5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string252 = /711ec8068cab80239b91cec707e3f811806aaee6758a536eabd0548d9a53d1a9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string253 = /7151e9f573e106dd3cf0b0741ce31a0247a8a2fc7e3e3ed6860a7aa836376958/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string254 = /7154bfcd36cdab9e802830e9bf01f34f87fe905919e669ccdb620bb5dc9bc90b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string255 = /71dd1a83975bb7020d3286003f6e0caa21f744f6b9ac77199e59ac5900a957c1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string256 = /7215dd73a9efcd1f85066a3d6d496a80cad0911b409847b524d4111e520c5d1a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string257 = /72d88f37a4b06a1369b21be40f93b18e929529a0cbffb29b91959582aac23073/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string258 = /730b62e8a099a320ff72caf2e758cb15b04cbb123cd9fe8cc72dcffd80b8f214/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string259 = /737bb1aff3cc22137328d202836fc2bca1f52c2bcae9ad2c786c8fc075a78580/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string260 = /73af2b231655407f21245cfd079ee28ba711ff9cece86a0965673dffc0ebaafe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string261 = /73c18fc9053fdaa31ddff70920e31ea2e638d3012eeb795c51923ca1902a6c81/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string262 = /74200b1f738a038ff90ec70377feb61c978487c71b2a9468d827c188fc33a900/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string263 = /74b2d869745f1f642e34d8f694da33eaddfb7c6e68ad9cf24bc40df90db834cb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string264 = /76571d635c03a27b42b9f28e8148012ee086518932b57e269685b0cad0148336/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string265 = /76de1ef6c3d47c7d2b1c05d493b60d2a846b45b7ab4c7fa162e54a94c24c2960/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string266 = /77e168cc5dfb4dd91c2512029eef1d0d4656df72961132bf0ba125fcaa86072f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string267 = /780848610f8c2ed5dc266cd51ce1d12f8049f580bba8ad403296dd93fbc22256/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string268 = /782811dcb3f37789df2dc8c60c65b59ac7845b0ba57d79f18d178c0a4cc73aaf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string269 = /78733969f8a27a92e4af2c9c835b256fdce1f5f521a5a248e16dafb385a68e6e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string270 = /797b944371e918b47143d0e4282033e057b7accf981ee5461652d659cccffd4e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string271 = /79e94689174f714187930b4003d27a11e7824508e295849ddda8dd94adbf994c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string272 = /79f9d6b67d810d18cc0bd093578cb11d26ce43801eb6aedb2933336380ed6452/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string273 = /7a71b37668cc866ca43cee0d1d0b51e35fca551c12648ebd2d1e44b021566d48/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string274 = /7b033c4458195e7b30ef1f85ceab1cb7cd67d6f37fda3d3ce5fb1e3520799fbd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string275 = /7c40428f6a5c9b8bc70387d5c9dfa173a47095f89e517b3fc0595807477b56f4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string276 = /7c7803b24a7fa83c44e34499b0cc7dd9098e8d636e52c20296b0751465c3f6c3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string277 = /7ca893ad65bcafd58e9e676559b97af9386b184af8127e0c9531660d76ec6ed6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string278 = /7cc31e4385fd3a21a506705a76c7e505730dba0bffeaeac42dc6796d8c2334d8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string279 = /7d043db474ba220857a9290cfd11fd6c3fd42cb39e8be1b03084840bc0320d17/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string280 = /7d46566153850560ca31a36edd46a33728d6c2422f9a9fec8efece7f74642f0b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string281 = /7e643e4b2ed8bc2dda5c6d450f16a8d2ca38ad306ef26c351cec58db97d237a7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string282 = /7ea18c700dcc3444fb59a36f589613bb97c3d17ed8ad43e005cae75d35e61f60/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string283 = /7ee75a2b8e9ac772f17dfc622e4f5011507648c0dc4c863e69a019ffff1da55c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string284 = /7fd016446b62d4ea4aa197de85f3f45f58cf0f0f85c1cd9d7bf37fdee27d182b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string285 = /800ddc434bc8cd851417eba662314bbf37c893ee3e3ab715da5fb386c29103f0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string286 = /801cf83159c4f8e926bbd62cce010fc436d5ed036f589b4269b866f6a3657bda/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string287 = /80d792752ea5235d98332ae1f26e897e7481f4d3c194b56d1a5bddbfaa043eb9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string288 = /8157255bd8b050e5875a4075e26ed8589d56083f3e944df98c3e2fa498e1bfd9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string289 = /8168c7da7b3fc4bec5fef3ad065271c250f383d202f6ff16a2d52c38135c075b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string290 = /81c6fe2b2271e9d8ee7921112070316d2855a2c73f5e78515f131ec6265316be/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string291 = /824887ee1daa53cde973218847328c1e159926dba2fb50fa3d5dff2b9d7c40c4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string292 = /82d7b3b02f63138b68de51799ba42b9402ed8c9d899d5c0ea1797ff19e921685/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string293 = /8392f4e2c944fbecade552f3bceefc426d47340a04535845ccc0f769801b28d6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string294 = /8423e2a9ddc243b82a1c52dd9b76d97bf4196c8da044bdb2fb06af6c1ecc4e95/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string295 = /84af149e112b1d379f2c8cc7261bf8fda864e2f3f37f0523274383c7c403ca0a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string296 = /851eca4c1dcbc7dfddce7496284df95a1eb57c9d6cad75bd92cd2afdae8054e2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string297 = /85687380038c8fa0370f374f5bf4e087c8a34c03aee886f938f1b05be4dc3efa/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string298 = /858655414a0c3c0a9d6fcb466c47a06d7c9f19c69aa5c3635fd25fd7f017bae3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string299 = /869e5207ba18cdc96d8d3ea5e90c7cf02611804929e416c1622c6072ebcc93a6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string300 = /86c2b33a1b4eace0a52da1e4ca7371de14c15ea2551b6a1d1c4ba2735d5cb565/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string301 = /87230dfc37d3e1c054f985f31d348b6d7ff459d976085843859e226d8723d720/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string302 = /875fdc51b4427def008cdd88a81241e4791eb002c7d70fd8b71084ed8b6831ec/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string303 = /878a57b1c2dc3321cfb5728358e482230b6efb7f08a116fb12ac0a26ce63335d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string304 = /87b841b9eedbe53eea82fdd3553b459fd1041d757dd1c2279429739fc9c8f7a0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string305 = /8847bcf8ffca87a3ca02bfb7947b5ad147281350a66b25bf5b5495b2dc7c36b9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string306 = /8883c36d251e050a0e232a171024b166f8ab5b4efa0f455fd987560fed85d175/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string307 = /89420ce0d71a81a4612e5bdd7de722bed41c31dbe4e0287e5222708f687d1936/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string308 = /8a14ac67d5d8ec601c353b0d7faebd6753e34f283797e201544ee5ef32317e91/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string309 = /8a76966ffd6c4c29c203928df3e585e3384588e7ea2a70ab9f6f6d1bcf16ecd7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string310 = /8b45bafd3a11fdf97de1819bdcfb7560f11ee1207562b1f53712a25326610b4f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string311 = /8b585057debe15045f4e0694e8fbd3325b7ad71ce2e20003d6637fa6e1c1e025/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string312 = /8b997891257e94a5dca93dd4b7341dc3a991d5fcd4b5730110abfa6c258d30df/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string313 = /8bb4a7173ed3c828b227597d1b59fe08410f19b5e16315cce383d76ac1d67b02/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string314 = /8bb8d1e02de80c343d03d48eb549cbf6a0a891a699c2c9e47079151817c93ff5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string315 = /8bcf672bb3ab901527e707e501bb399874fc6558320ecbe00d311d308c5bad89/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string316 = /8c7c04928a927b1763b2ed933232863cd3d7a4bcfe787425234cb8fb0d499f55/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string317 = /8e1166362185fa69479caf4b8b153f06799c7143f6b726f9dc5250835f979d62/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string318 = /8e3d537a09b98a466d58a71a21a3a9719bde8ced6344a2a0b7ef96fd6a9a06e1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string319 = /8e78f65f698f4adaa1ee3e14a5327a7ca7372140f82240d8cc40e753a172a9db/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string320 = /900b0066aed8e2c6c6c59122831b0e7ee4ea0328a5f8cd7a5bff739ef9cdb366/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string321 = /90b52aad38a002bb07581fef1caf777ec188fe07dc0f55d828a21ad35ceca48f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string322 = /90ca6caa7db1d3998a25b3bbc22526452dd7114bc3b4a660a20f842f8ca50258/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string323 = /919057b3379f84209626166b83566ebc0b4b663f6f142bdfbaa303250ca3fb1f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string324 = /919c2ae72cb629fb51f37c1e9fff1b24a01b2026b58213ad88557e64e8813d90/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string325 = /91ad0d9c090714cf7af5de1da071cf52960ac058a0f915ccdf8f2eeb73661b6c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string326 = /92c92547aac24ad94bb31551d0d8625c7e30c6b9e88ff542f2a87d9dcd4b08f5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string327 = /9402ba2248837d50c00f4a423ab23b384fa81b30e6a6cafb86e9cd73a643daeb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string328 = /946f91872edc2694cd84df5a147df89583d29ed991e8e80de8ee219ea7635528/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string329 = /951575758d87951838e7afe524f008ba71c75b88738c66f7a753f05d47937017/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string330 = /95451ba9e548f9e140de232b85cdf6541438e20d7c58e01eeb3011b87dbcd292/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string331 = /9555ccebd8cee6d9f1d08bc5f2386c210cfd3930553e153f567a1d1d12403c29/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string332 = /96025a3ddc00d070b0ff8d470030b172d8308395dc127f51bdd6de6154abeef4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string333 = /9629b04d7ab98df29ab630e392f7c15a3a3e050e4156f6ed60eb8aaf206af76e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string334 = /9672225f3947d30a1f5c29622c50e8bdc29b749df23450dab7f1ea3ba0f44d5d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string335 = /9685d4a085acb3880294d902b64562841b163b4949ebab8109a92ff3257abc60/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string336 = /968f17d5151addd34a19ca654a5ede75b8f6d0f079a3dd967cf2f857bfeed193/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string337 = /96b452bde52ca91033ed91f188d4c4e0eba7976a217bb474666428ba84f7cf3d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string338 = /97d5f4e3388f23242edbd69a62412396e557290ac5b8f468c625255fbbc4546b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string339 = /98456f61bb55fd826a5def604590780b552a261249ee82cf1969008fc67b40bf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string340 = /984f119adf8040c9c400f4fdb937bd99a7a26ce18db101b330472dd9ca4b52f3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string341 = /9861d10bbed4f966d0173aa361530189107a31e37478464d8ef4bda189252214/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string342 = /98c5018947477f613943240fb4c19347e2ca720850a078d959df5fd3be8ef4dd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string343 = /99187ebc1fadec7a7fdcd0a201d75776efb53514fa56b515cab6ca6e2783a402/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string344 = /99fe09aeebf1700973742ff24b0d99708503e8f584354b3c8ec784ee92c0ec4d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string345 = /9a0c1767ec9ea7e8fb94abee10e7094e6952248671ef5977413dc2a8cbdd20c0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string346 = /9a48f69510e0194b5cbdcf9a15335b3db323c91898606e21ca57eae78d2bd27d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string347 = /9be156f2e68d672cc00a2e419484e13e6873ea230d83caba801f703fbbd02e64/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string348 = /9c3c1eef7d60285aad7b4d948847b9cbaf3f1676c6bcedfa40ff5f9629c8c5cf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string349 = /9ca943aed529d280554f86c58cd49fcfaf759d424cc64c9c062b6ab90de79e7e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string350 = /9d07db60cd26c5d11f94aa666048b66948004a660ffb03fa7c3414e56f70ae5c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string351 = /9d1f61358901da13ce8633966b867195a65b387169e5a019e6983f1d69290c4d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string352 = /9d404660d091df7a8254e54ded6f39ed2b766b7ac4b08969b5b9db472c6a206e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string353 = /9d40e53bd79a33c9124c6d9e89e71c6ad329f180b2e73692daf82846ac1410a7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string354 = /9da97c98754e746fdc15a562fec6b6c0374007d2bf3b89d53a15e82b409e724d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string355 = /9dede3f64f01a53799636a50ff9f342ea1e2467771de9eccc3a1cd36e33db476/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string356 = /9e67ec011613b7a41c197b89e1affac2f3d421a91e89e64f0f4ba195dfffb3db/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string357 = /9f25b9fee359a51b7ab3ac889decc51cdec9dcbeffb57a3e2001b9dd263062f1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string358 = /a05461fa6d819d987203e7272cbf4e3eeb2879f9a69b27c4b5783cad1c4af29f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string359 = /a05ffecbaa4ce2121ed7ea1a8181f34d41db9fe89e60b800e20eec22631f576d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string360 = /a0f3b76ea770d4e850a7e3904efe22f53d348cf40767e279d873ffee5ae89a6e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string361 = /a13985069fc38a1a2d154f9da033a5d6fec33c74f29b301bd283459207bfd4ac/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string362 = /a373aea915dda9f79a2b5467a45a9457cb8595b756ffd56b98c877733e0f14b2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string363 = /a3db26ef5003ac7b18f143dd6fe3c5ab789cd6cbc908f7cf572d006d9f8bd133/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string364 = /a45aba3ece9369139d34d85d5024d057d98134cb72b23db28589cff428499763/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string365 = /a489c0ab41646b1e2c65390196f453b4aa04ab76133711a264ae33ab8bca0026/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string366 = /a556e82073a4932a5202e78699a2e9db62afd3e3d0b9361f915d3b92b9d821d9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string367 = /a56c6bd3f1997f0ed36f75f019637acc01749de3a31a7ffce345b31e8c02860a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string368 = /a58fd21735ae4781c5aa58714ac26575ae954aea83ca2bd501439f3c0416a1fd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string369 = /a60858741df25450db9e46aa870a04fc3be70028fca27cb75b89f642e3ef31e4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string370 = /a67543b2c8434f6af3224b63e88885c68981e8145729c815505d18d31f0a49ac/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string371 = /a714b3a2ea1103e9571476a2d6c2a2063938782d5b2f362b19854572551ec6f8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string372 = /a749e86de5d9f621605a3ca4c2e57a90a03e40fae39b1bcd2025116c0e228962/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string373 = /a7c0d88a6a39881381ba63b7061a03dcd7ebd2dc83cc7d6af914140c559f3e27/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string374 = /a8ac4596bab404b9c23d9551f2a2b5922374b7e1ed8b382159f135ffc8bce8f9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string375 = /a9084eb399a2429615a76b1d33c22452ee5827d736d849744f5039368e8c0984/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string376 = /a95c6bd632b23c5bc2c7d9bcbe95b69e1392f2377232254402fe7d9568eee172/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string377 = /a9b3834be408b66c53b125a888e0f98899603fd79fcbe980dded3c6896d9bf34/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string378 = /a9b451f93e8ead69f036bdc262bf7700b2d18789f081bf3c678da72233730cec/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string379 = /aaad2f2baf694d48d712e346588654b34efc098d6443114600dc45621aa590b2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string380 = /aab9002fa530e777ab0dac8b5aa470d6733f1d54d2316c58db6e244726b5cf19/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string381 = /abe2f2b0a57474c206676b14aab4801779fbbd421357586ddadec94cc5d79707/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string382 = /ac208550f9e5497ef437b924f8e284359c7cdff98f2d1924d212821ae544940d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string383 = /ac4638d1cbe7a1db75e200b8ef62be5b5311fe858450d7562b86bf94c17d1d0f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string384 = /ad50106f03dc12f69b15eab5dd76a917b4200f3d02e7f25929d6194a5da965fb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string385 = /ad690f3c67428e406d7e39e38b1e7c0569eaec1cd488a3f81c49048e9758cdf6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string386 = /ae4ef59bce3e71393264a4cedbeb40bcfeb518740048bf4b619fad20f24adb5a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string387 = /af0620ad11ab2327d91c65e3d5feabe08e2bc7bbc11099322f5eb4c7f302c4ba/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string388 = /af5953a63d8030e45758873c4fc3deb688e800caca48b5dcaf3fc7fca6aa9ade/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string389 = /af6678b4085b9c309c3c6f2977426aa104f796b083572d67cd1a71b8076af28d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string390 = /afbb31d1093a2da538a7179a04ccb87bebdc041734314f027ff0c3d2bec04cfe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string391 = /afd6ae4a43475e4583b50a168a89eb3f3ff3916fa2a9933c41581bc695a10796/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string392 = /b098cae09f215cc8ab24cb98bf217ae55a61704fe0661847341a11656368c7ca/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string393 = /b17179a11cd25646af11ea28051b799bdacfe9fac6d66f2cf6e8dc1e4888916d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string394 = /b3c508a09116d5c4b63ea3b64ba54585a92ae84f3f94d73a9528b47357552da8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string395 = /b4365f5c1b052eda101ce80a2184f92fd3a0a4d9c48255fdb7042ea7a4810fd6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string396 = /b58e5bd0a4f4691d791c3fc90885d0c36daf28b4d22a8a04d25f4cd221fb1517/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string397 = /b5abbe48ab64e19472e5540d92810c40a2f79484d96d5da9e7e8d5581a01afe1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string398 = /b5f9c922325f283dbf3ed921d4584b35493ceceb8b0e750cb250de96b0d5b7de/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string399 = /b62a8838e1abc2ec911eab920f3adc7a7e7d9f5e43daf520e868408e069aa9b8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string400 = /b718d3a910fabbc4b525692d01c031565b84a9e6d4d4ce2a5df0dd67170165d0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string401 = /b764c55e619f1368b2b6ec3af8ce4c799a56b1d0d9e1fc19d2f204f7a94d4424/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string402 = /b7eab05d2830689b6a72af875085366fc8116fec2c856c7dc5af728bd0b6b972/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string403 = /b83bc4961b33aa3ec0399c801a97c2c47766462991ffa488a4cbaee1ab3e0bff/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string404 = /b89f0a3b10b8b73f873fec267286a6c006220ea2a7163052b25cb130cf38086d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string405 = /ba79187d6d0fbec4e1b989565e8ec192547c400826d9d3fcd7fd4b4c506bbe27/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string406 = /ba84810ab6a2d27ffa9303915bbd18e1703d032dd133cf93ceeecf89e2f59fe6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string407 = /bacd392be7fb78662fb91e354b4d6443e824d06ae47d4819b0cdf657c8e02eff/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string408 = /bc379f273189510c10ca5c473ca78ce246ac734ec6a376bdca7e0ddfa09804f7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string409 = /bc9c9c452084648c29a0ce2b6457b0ddf03bf4f63d939797b10eabb4b470e31b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string410 = /bd02d9315cbe275ea1057def4ddf72731ce486980ad768591796a0c112032e80/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string411 = /bd70867a4f0b2aa9b06a7e08dff5bede3922580c26f366a0145d062b55a6b8ac/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string412 = /bda266f1f529dabd975a6f974a732dd7d9de3db2e3c8c2322985c46dd3f3c01c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string413 = /be6d0dc445a00098d6cfbc537423ce23c49b4b08d530ea11709e617636c883a0/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string414 = /be9b10dddf393c3c4abe05f9237a0e97a8697da407505b192c4385f01e8d9615/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string415 = /beb8955b03b3bc379ad4fb6df1d54b1b5c0aa7226a0f2036a9cfe9a4eac5b488/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string416 = /bec3552674f4aa1fe8bdeb2776005fb3098de9a86c22d81021a09f1ede608a5c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string417 = /bf493db1ee23d91edc7d9085c6a37052e3d82c5a471cd6a9fdce92e401a89090/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string418 = /bf7004986efeeea71925695379ab87a74e22cb0bdab80e960fdeea8ce297fb9e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string419 = /bf718d8a798eb9c98c107dd999d82a9326f152cd3db9a50d7b776f6a29033631/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string420 = /bin\/tun2socks/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string421 = /c001ef60b326a1b510e14111fc6f0d5639b47aa0d842e73f52935a9fffa794c5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string422 = /c022454abb2dc5b52483870aa3a5c8c9e3da094780205735e927a17eaef7b351/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string423 = /c06a0f5ccb8fa0b7aac6360b6ec7566dc06e5226ef1de0f7071a5404ae8d0c07/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string424 = /c159cb0a6a05145cbad83d2a4f12781520546f672dccf27361d40b3cf9c59ee1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string425 = /c17076b7aa8e89e2b403234e0873f24e0c784a783ad30fc190091f792dd2d3dc/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string426 = /c18d399ff853bce9a6a0bccdd5ba741639556d61694317a5e8d33282ca2b5c88/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string427 = /c1c15496ae180633f6464c67cf86603d64b662d674a18f8c9e9f19c71d74acc1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string428 = /c3050fc06df213b534dcb6a9913efcd33c2eac91fd36467ef39376d335dc9c2a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string429 = /c36af69fbaa4c7daeb9d54f037f6fdc9917069483570081c6c094023b47e375a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string430 = /c4614aa579c4b2bd0703218c1e8d5cab85c31a986278dc909edee7ca00687a3a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string431 = /c4913bf62aa78117b312fb37677f5b6d24bb96f22b72a3d0a8166d917f21a3d6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string432 = /c4e2c901b28da1a3c2d5b4714a9f11c9e4b9f417c1be73290a14a6d622607f78/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string433 = /c58ae1aeef1d895bfc5083722ab5e5b9e097abf48426d8c1210017f94a6aa8e1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string434 = /c5ed7048e6cebc2b7612053b0f0a38c0375ec30a13a46d8456ccaeba7ba33ff1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string435 = /c8c03eac6f580d5a5b06e41e3893f9addc08b3ffce06772fe997df705af91cbf/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string436 = /c9dc3acf51b8cbfc14f4fd6f69bd3743d695c8e6013736a5b336ed6200c7036d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string437 = /cbaf0210687d757f1633501c2706a4c7e58ce7eace047c9baeb720abc83e9528/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string438 = /cbc4d8625c86cc011647a533bc6f8667bf16547ae42cf7e01a48259ca507ac8f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string439 = /cc16da8e0b3d5f3f107f25413a2f0b7c71cba43ba7013e68a269e1bd96c34b65/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string440 = /cce28e2789e65c0be2fdbf5605521babc06ada19020bb00d9314cd37757854e5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string441 = /cd93c81596eeaa53c9d68afb8a2e6d348ed2401008f95014b86591041632b093/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string442 = /cdaebe0f3e4166ba3c1575c01ee614e6d2492722e395b60414aed79ef59d84ba/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string443 = /cfcf2478b9522b54a9af162dacde8a1b7618f808eb711ab6c1a44191bb044f31/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string444 = /const\sName\s\=\s\\"tun2socks\\"/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string445 = /d03701f674555a2d9754d90179f2af83782a2f647e8f8c2355e8f8d7d9c84870/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string446 = /d071605c35f25451217ac8e22521b986d9b478e520abf91320ce39fda8b16c0a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string447 = /d0a3532c8dca1cb65fbdf7f28818eb5543a523c7eeebb8cfc838862518a96b51/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string448 = /d16e708e00f1d0138dea021571eed4ff2f2271ce937cd04adce602bbff805b8a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string449 = /d1f2f22cdf96f4a71b8a859353a8ff4a27d4afd8f8849da5d6eed966c1cc72d3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string450 = /d1fb9e6003ccd810b6df1b2160dbbf6ab8b6daf81c4cbde95a31add2661a59e2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string451 = /d2ba2c40a27cc310f8369bd19e46b5efcf954259bf229c30f4fa24f661f49504/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string452 = /d350f54074d0eb76f3568b2983c1010cd7190f327a5420034de0ca4ad04c6dbd/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string453 = /d3c1e10f04b8628fe4f739c7f59ffe38433786d543c9a8cb2fb0b85e1bf0912c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string454 = /d3cf1621c8b439251029d7652b385722e0a7accc8b9877e9fda80ff1aae6d2b5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string455 = /d43c57b216147ed60b4f3ba8a9e9543761492057788d64fef896e5075249630a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string456 = /d4579c7cf34a278d9c70fdafa36ca0ed47c8c7a93c876901862fe3ecfdede336/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string457 = /d4d2f64500f4ef36f7ee8bd2f7b580e143f811d67e8d9b60b680f4fca04a15a8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string458 = /d66d64d4f3db00002708c51dc67e916c760e749f71c32c0a35943106371ac654/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string459 = /d756b55e894c289704c0f4b0a92bfebee404bd1047494ed81a1948f7eace2b26/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string460 = /d79d89c9bd219dce8baf10adc6a49d404d135228a8bac6d04d9c1a77d6d0b9e5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string461 = /d829c805dfc29e54769382a8d2378a133cd21627b97a60e2d835ff8d6bbd203c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string462 = /d89d673d364fe861ce88027d3cd7598d64b2bd68f5b3b1e85bcca27b091de5b6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string463 = /d90f7aa9599ba9ec2b9d356db62aed30fad6daf4df8075de7b2bb7c585fce67c/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string464 = /d9b41241dd303f1ab21a96e85254e237e3fe95e9a325ccc1c87bf2dafe066427/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string465 = /da1198d8820ab8ff3a617970dbab3f1476c90a87f69a6deb98dbd02026f7e829/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string466 = /da9ebc9ba59655b365203b0a48c54ec230ddc0a539bd5b3feccab19a0da5127a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string467 = /db5703e3f81ef1ebcff2242d0df019c926107d4d062617a76623d6e196285539/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string468 = /db61c38755146ab83aa010beac56737f1f1efd74c61ebbb1876173e29fd1a2b8/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string469 = /dc20294fe264fea6841e0aed2560f0b995070f9bc680d170932ef50e05ef0690/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string470 = /dc6471615591b2fca412d411535f597485b37854f602dadac37da3aee4fb0e45/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string471 = /dcbc3efda3331913ba98b1d4feefcb122b5f7e3717b4c57bcdbf10eefa273aae/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string472 = /dccbd0950837123fe57b99b394613e19cd4f4a35c26f4bc31b8c952272f213d4/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string473 = /dd4f3e4b946d9f070137a899653083858ae7a973d0c3c5c2dde1c39e6d44e116/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string474 = /dd7c138a3ffae91a5a0ad5bc4478604951c7c2250c2ddadd975655b3fb9b988e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string475 = /dde8e9815b11bced6601b6c0b11235c1c3e6d7ab3196634db85566699bf9e1e6/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string476 = /ddf4c4af21b0ee3759fcf48f9adbd06f818c8f3058470e5861f760e629992400/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string477 = /default\sNIC\sof\stun2socks\sis\sworking\son\sSpoofing\smode/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string478 = /df8ef60e1804137b954c9ca3f896887789d33fcf3c24ea31db30a18443370539/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string479 = /df9860d2c8cecab1cdb3ea0367184c4e486ae8db5661784f94d5bed0736703e3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string480 = /e070581ad8dc1ca4c1ed0a4372622a03f807fda24a7cf4856e77382c8ce43c4e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string481 = /e0813810d26e45cd005e675ec628615fa9b6ba8b3c55ce002a74a8ebe143d133/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string482 = /e0df786633e47059eb4200a1b521acb4b496006fca3c5d511978a71df6a8d976/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string483 = /e12a9da86cf1e978789039ac79e8962af396dfe9c71db1aba39caed38a7f366e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string484 = /e145a82842b920b4079c118dc86a28e268876701ac743a9b234472375037bf1d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string485 = /e31b89233aff02e3c31f7b507c212809cf987636abe5c8d28ccb66dec9bc976d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string486 = /e45bf8db8dd20bb90ec257016dbe93831b8adbf13b1eb7d4eac496b895b3eddb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string487 = /e47c1d1be0e70b9496873b1b78c7c185320358fa94cd8083e09931de1d82d2ec/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string488 = /e48ef8fb95668ad11567f9ed959552466b9fbc796fe8380b312a5d165843048d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string489 = /e6359a7bfd1ac7ffb8432de776f66ad70e20ba588880e641613aabf29dffa0c3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string490 = /e6e7406f1de4d3797e83f273c669296173e754769dae206c47eecd480d722f62/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string491 = /e71d6323db9dd7f3333d32a1fd6675108150e12a8d8769ccb8e38628a9a1aa3d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string492 = /e7670b3696d9013f88d2bc0f35aed4df5fa68d30fecb7aca4a33511b76c4286f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string493 = /e8551730a864826e18b2283e7a5a24fababe9de86fa88974c4c5dafe314e079f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string494 = /e8831136f2ddf051e2b1e127ff7ebec5351f9a5a33d80289343ddfee2fd1ff2e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string495 = /ea2cd6a3926a99ffb0053a14a21829b88d3f62cb5290bf471eb21930041bc974/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string496 = /eaf950c4c33d4697237cd99ac67b9050fa2c4d90c748f5c6582872ca1b0b7ffc/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string497 = /ebf98b345bcc6ffd230e9ff5554fa32c998f0801ed0b1d4f2bd3c2e5bbf16a8d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string498 = /ecf31fb8345ea09312964922c549238664485b5593e9e79fb823a3b996c1c5f2/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string499 = /ed627e5d0ac3faff24ef080462ada798749c5d7a9ecd6ffda2b2e14251de3784/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string500 = /ed97a4ca8acde3b070985013333896a1c55fb5387233c2fdbefafeed2ccb9c74/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string501 = /eda049d723876d9783aa850feafc7aba3297ff8af282606d2a8c899ba591c7d7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string502 = /efd837fd57626e278a65c495567160835dc8ddb29675c71c68c676e57bdc9b98/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string503 = /exec\stun2socks/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string504 = /f089979c1b33e75e2819d1fe15e8b50dafe0c075a5ad3f98207b51bfdff69c77/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string505 = /f154fc90b680ec716ea189245556b03b214e829a64b3f4ca23ca78beb4701171/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string506 = /f1c145f20ea495e5d9df00513b6fcb05b2dd7e0f7f126626372c6d65b25ddf76/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string507 = /f20052cf692339ff89a490dd7d9f83f5b77be532d5f127f6ed186cf387622ed5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string508 = /f23ac192b0a075ff7d7f26185c99b21cfb1b46ec211e67cdae626d200476f3b7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string509 = /f2c6184aaf6255cbac03af0f218b99f1937a892ed268c18d718546b34f2121c3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string510 = /f3ad17104571c366fc2d5f3cacefdfd3cbc3f47195773b652a8c2eadc41624ca/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string511 = /f4720596cdfd58bfde9ea3d21d676a3fb5722bf838007848fea8b7d9584dec8a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string512 = /f48518cafb0be8696453cbb6c92dda93d76f5f67d919bd6a21e246fd68ca61b5/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string513 = /f54554998f7c0981faa927601ff8a17b8ab48e6b8cef618df50c9f6d67c45e91/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string514 = /f57a182a690a6b7f1aa7cc9cfb880a3f252cddaab6aaeedaedf0f4883b4104b9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string515 = /f5d083622d36be251b6826886fd98b56b573e260db0e113510afcc648886f104/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string516 = /f6f8e3cb6081848ade48d449319f92832c45ecf01a7df1d3400bdf0a275e7e32/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string517 = /f72fc36ad8ba09bf2a911d35badb9d702835768087889bef378285e1d088cdc7/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string518 = /f76cc170f78f8eb5d9c264e92761e1ceb26a50672c8c3372a18113b51f1530b3/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string519 = /f7999c6975478cdc9494892dd265cd24801576f46b33bb72cc9c942424d63e4b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string520 = /f80ec70060c69474dacfc625375022594a7089ec7e18c75ff4c070c4b5d3187e/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string521 = /f87336f0cd0348db4f5054812e538715bdf5f9306ceabb28a0f5763cf24959e9/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string522 = /f9fe9036adf02a76fc87d26245d0b8db539a16fc4b420f0a7e613a68a1f1ede1/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string523 = /fa13cf651b92aff3ee0b74b557c9751444dabef783e511dcbafc15951cfbcb01/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string524 = /fa198e37820eeffb222b11bd1c6ced342167f1b6c9556aea77a048195a3fa74f/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string525 = /fa63c897e614a228f3b176c98d8dee797c8df24ff7e487b023715255621ed292/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string526 = /fb38cc904ebf94d6935270a46826254c413b9bc8cd69e9bafbe03998cdaea129/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string527 = /fc1b0c344766d70255be2cf421039e8f20476ea852f1ab081e81b525cfd989fb/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string528 = /fc4be26d47f3987e20a033c7284632b138b9b05779eef26458e234ace63d67bc/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string529 = /fcb65ec936e24fb138b4d40c7223331de958b67c7e7a0a5177ec2d34ba342e6d/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string530 = /fcba4c2c8de3766ac07bbdb3933257cf8d374a956c2b9f95cdcc7cc6e12e8423/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string531 = /fd0d7ca03da27a8a9994e2d7238f864fe4bba8a1fe714e9f2fd9817368f7ff89/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string532 = /fdcd0eb6e702e697cfda7697b058232f8b0cebbf48dbaf5fcc284ea1ca1f1b59/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string533 = /fe798793251dc5cb179923e733865ea5cbc2f4636a849111de78930c199b487b/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string534 = /fe7c0b6a562e3939e5ae246876cffa6ec2f7c45e70154c50ed8afc44196c7a08/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string535 = /fe8498483b5c12b580441a1a03602e7087b2387ee692f2648c79023864985e65/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string536 = /ffb4cbd5e7c7b0b110ea1c96ab0d961f40ebdf5adaccdf87bbd34bf75420ff1a/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string537 = /However\,\swhen\stun2socks\sis\sin\sthe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string538 = /make\stun2socks/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string539 = /tun2socks\/releases\/download/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string540 = /tun2socks\-main\.zip/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string541 = /tun2socks\-windows\-.{0,100}\.exe/ nocase ascii wide
        // Description: socks tunneling
        // Reference: https://github.com/xjasonlyu/tun2socks
        $string542 = /xjasonlyu\/tun2socks/ nocase ascii wide
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
