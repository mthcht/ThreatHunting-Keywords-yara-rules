rule gsocket
{
    meta:
        description = "Detection patterns for the tool 'gsocket' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gsocket"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string1 = /\sGS_STTY_INIT_HACK/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string2 = /\sgsocket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string3 = /\sgsocket_.{0,1000}_all\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string4 = /\snc\s.{0,1000}\.gsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string5 = /\snc\sgsocket\s31337/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string6 = /\s\-\-remote\sgsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string7 = /\s\-\-rm\s\-it\s\-\-name\sgsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string8 = /\sssh\s.{0,1000}\@gsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string9 = /\sstart\sgs\-sshd/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string10 = /\sstatus\sgs\-sshd/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string11 = /\/bin\/gs\-netcat/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string12 = /\/etc\/gsocket\.conf/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string13 = /\/gsocket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string14 = /\/gsocket\.git/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string15 = /\/gsocket\/releases\/latest/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string16 = /\/gsocket_.{0,1000}_all\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string17 = /\/gsocket_.{0,1000}_x86_64\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string18 = /\/gsocket_.{0,1000}aarch64\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string19 = /\/gsocket_.{0,1000}arm\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string20 = /\/gsocket_.{0,1000}armv6\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string21 = /\/gsocket_.{0,1000}armv7l\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string22 = /\/gsocket_.{0,1000}i686\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string23 = /\/gsocket_.{0,1000}mips32\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string24 = /\/gsocket_.{0,1000}mips64\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string25 = /\/gsocket_.{0,1000}mipsel\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string26 = /\/gsocket_dso\.so\./ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string27 = /\/gsocket_latest_all\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string28 = /\/gsocket\-build/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string29 = /\/gsocket\-deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string30 = /\/gsocket\-pkg\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string31 = /\/gsocket\-src/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string32 = /\/gsocket\-tor/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string33 = /\/gs\-portforward\.service/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string34 = /\/gs\-root\-shell\.service/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string35 = /\/lib\/gsocket_.{0,1000}\.so/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string36 = /\/raw\/main\/gsocket\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string37 = /\/root\/\.gs_with_tor/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string38 = /\/share\/gsocket\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string39 = /\/tools\/gs\-pipe\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string40 = /\/usr\/bin\/gs\-mount/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string41 = /\/usr\/bin\/gs\-netcat/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string42 = /\/usr\/bin\/gsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string43 = /\/usr\/bin\/gs\-sftp/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string44 = /\\gsocket\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string45 = /\\gsocket_.{0,1000}_all\.deb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string46 = /\\gsocket_dso\.so\./ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string47 = /\]\sGS\slogin\sdetected\.\sTotal\sUsers\:\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string48 = /\]\sGS\slogout\sdetected\.\sRemaining\sUsers\:\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string49 = /00b5a02c0350f67ee2562d63461f29a2907e3e991b51a0fa3e424b102b1cf552/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string50 = /05fb17382f049ded33be4d8d624a2b3cc246ab0814e44f07352c12e1880079b6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string51 = /06541ed5fb95052dfeda2cc6165732d1c125f9b49ed400f578750b03a67c418f/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string52 = /0a5e1abf70407a1de22cd14107dca8019bab45e8bfe4c45ca1e05e7e8bb92e89/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string53 = /0ca53778e8cf399b1052ba2f500881d04066525b65e8b564360e7b581ac9cf68/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string54 = /0cf7ec1618e87248f23674db07692a63fbd4e945102b143baa5b34d7eebb5977/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string55 = /0da3621a6676dcb4ac7e260ea7280a14d05c9bcc02c0a296a6507172a3cc7bd8/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string56 = /0dd41d5c99202fa4387bb5b9db7ce55236fc913b65e3a9fb58f697d3480f14ef/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string57 = /0e95446bac57b2a3276703c700865bf025f1eac27bc5c9ebcf820c1e351b6732/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string58 = /0f948584d230abb0e870a4e46541cdf4dd8b60f23fa7e031d27cd856bc49b4c4/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string59 = /1106565073956253736\/mEDRS5iY0S4sgUnRh8Q5pC4S54zYwczZhGOwXvR3vKr7YQmA0Ej1\-Ig60Rh4P_TGFq\-m/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string60 = /1160bcaa562e5a40c74e633ec58a2518b110e74b1d3f48bfa06f74f72cf9ff98/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string61 = /11f50c95d4dbcd97d5c76753aa7bc38bb615295f553a4c989015176ac0fa3be3/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string62 = /155c711cf850d024e86f65be8ff0f9e7e0e947c5632350913dadf8cc678909fa/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string63 = /17eb30ef4d91991b265d5d93ab7f4ad6b58d43061a46ba3292142b962be95f7d/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string64 = /1a1be3746ab4055e51557ec20f236da58a4dcbe1a523c8f5a2cd5dc97e699533/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string65 = /1ab1fb9214bf799302b9204b211eec714d0c1fd551ca45adeab8483a350719a3/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string66 = /1ba34d4d223d6a532c194e578a3efc5e8aeae8bf657223614c502e28d84942cf/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string67 = /1d4c6a6ae56e7a9983254e4a31a368ebea653d96277466ffb8127e8ce0b54369/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string68 = /2028fe2f9036b7fd8f192b6c9844acaa40bec1f40cead52c0ebc5defd9255f64/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string69 = /2042b3773e03285939fe7f0d0597a77c8d4958644b1d8a366cc71d384f1e5c30/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string70 = /22f6a8fb8771a0ed253a3652c6852a831b4919b2a677ddb6a6d03cad6a0f76f6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string71 = /22fdc29d790bb072a0bd54651adab4892fb1df1c75fb44388c3d6a0b0506d908/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string72 = /25cf89a0105c08084f05df75a9dcd1c239e3ec07cf5b36413c04d204393b3560/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string73 = /269d5ebc2a387173830bd5aa8f622c4a9787ff60379bcc960febfe950927ae72/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string74 = /2c25e65ae97f9652d4ab24abcc8c75a48e9b0446211feaeb0e8b138176086ef1/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string75 = /2c68f74c83b924d84b0de8e4a75a44964ad5bf934d3b9ba0baec9732b70183de/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string76 = /2e7d5dfd64c9741ef27284fa9e9e20f84da15669b6979daf730974f7da356849/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string77 = /30d80944d6e4ecec3421db4532a9a146f882e381454e2e09ea35845a4da1f9c6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string78 = /37328d4092b0c2cf9e23443a1575078c0a072e0ca39382e27c8e9c177bad2048/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string79 = /3891197c6740b1864b7a01b8d64b917fded55d40516b5e2774c92e92fc2ed5ef/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string80 = /3906359d473ef56efef773c5bcbd0c8f8df1b3f18e90fc0d0c8f4c2112706ea9/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string81 = /3b73d2414403cb76345c4885921348b96a63499c04027df1cba8b9825959bc1e/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string82 = /4104657745ea61b6e8ea8e468968e96bb5b266abedd73d93324ce14113edcdd9/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string83 = /41aad6daa162539ca954357d9477850ccc5c1f3d492fafe09091c7419d35a441/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string84 = /44b40a461af2ad711898a48285e333fbffd459797e4b24b4fde92ddcbb2196ae/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string85 = /453485f59e550e5ad903796a7fd65c0e50c0f3977d635f373eddbc3777d70949/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string86 = /48f6c28eb0f6be7a624095e620820e21cabb7008c14beee1210d930aa3d9ffb6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string87 = /4ad964e61bd5f63da0f48dfdbf4252550a4a8f894bf3c0813b3eb0dab6ac73bf/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string88 = /4ae67074c52164526a351037946fd4deacd275b5fbdea7e49845e9f201ac151d/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string89 = /4b532e80f16904176fc50b312ca8114d8ece3ec594cb34a29d7e5e0d767dca59/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string90 = /4bb77a1ecf1a057a39bd8b6f7b3f349717eac5d32eb87df25e29aceacfa1ec7f/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string91 = /4d6434d5a809c797570c59fd91eecd4f86b85e46cc6a43cf186a10a08db5e844/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string92 = /4E48vR7v8OUJO5OEYkOUUZmF55UOYVqo9l9w2eRS50k\=/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string93 = /4f64f71a7d6b8be79754e7bf2109675ffc8a3e37a4a55b08c95a1b1d25e458e5/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string94 = /512c31ebafb9013dfaf82b0123e088f976d3c1b57658ea60a7c8825a1c4bf7c7/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string95 = /561cc9eca17d61f99abf5fd5257bed4a8bf2d4c8c67ac731f5f067cf5f88e230/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string96 = /561cc9eca17d61f99abf5fd5257bed4a8bf2d4c8c67ac731f5f067cf5f88e230/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string97 = /5a86428ea0c5d6424b44518fe411e2a8c795d201f4a6df3b77b04f2af8f2a911/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string98 = /5b4dd71b0d9ac18c80db2eb0149e56af6b01533ff1e7a28359ca2f61ee0f8c8c/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string99 = /5bbc850a274b933a4e8b0ac7d5bc8b0527c3eddbaee7f8a9389c284f27a6fe14/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string100 = /5d6beae72888b5b7c4d4d6bcef2c37256c736435fd1b08ff642ee4c60a310ea5/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string101 = /5fdc26ee180c18e799e436da359f24c54ebeb91cbb5206b89f3c82b0d28b93b5/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string102 = /628e139e7f12c2e5cac243778c3fe428c878aaf690e64cf650e0be14915eee1e/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string103 = /64a7c5e1ef0e19140bf06ba70e0255f53c67c117ce1b072f46c30a1be44ff671/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string104 = /64f0fda500b2a622279f62bcc86e5282b9e6c5ee8e5ef55380e3a08e55b5ecc8/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string105 = /668718b8b09f631c3f1fa81519b99b83792a2e84d306296997a28db2e4f90d8c/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string106 = /67552b46f859511333d63e26a980b251e458c474243aa2af4c2f697aaea3680f/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string107 = /6a8351ce89e27856e20f04a2500f9a7851ea05113fb6babb4f359aa7a389ca73/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string108 = /6d0156efe079ba8f6fbb009df73332e5dab53955613b1795f09b431cf668163a/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string109 = /70fae385cd6c9bbcc73c17efabd236f0a0bfe00d11b0c9360651ec7e4baf42c2/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string110 = /70fc96e2f1e0cd752068e94fb4f37b3f19d670243921f76b0f2114578151f1e3/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string111 = /74f93a2398222f802089239c9610a21ea5ff34fb81cf6869f58bf5782ea5127f/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string112 = /750b490f1788db4c843135e409ae3175cff1be5c61246341eabdfa135ac6c7e3/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string113 = /75a064400fdf9acdbedb430ed009b961041fa379b4f219304477102f9f3d4281/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string114 = /75f3f565f1024b367a72a934cff9735e3fd9311ce5ad77de20c103cc72442edc/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string115 = /78792f8846332fa4d48b2710fd1d5d0bc6dd1fdbd62fdfed2c9aefa91b486547/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string116 = /7896c394ae338f34d46c51c5403ee41200a3fb1816763a4763c1228a72febe07/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string117 = /78ba173f30785ce45c8aa96e9cd13578d1db9bf48bece39a50617a8a49dd80f6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string118 = /7b1f95fad0a9d54d14ec51545fa5739a6b0764117843a3d468f387cfbe133e6f/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string119 = /7e6e4d4f8d52c0b8ed9b71fa0d0fad11872d1ee4204fc3f4835eb70932047883/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string120 = /813342bc9592e0e2b5672eb84376b59e098cc45929a42c55bdc96750f2abd5f2/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string121 = /840be30a16f12a6c57f8f68233b6aedb9e10e7dda76b1024b74fd660f3a13cd4/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string122 = /850d5195de840280e1638f121743617ad47852109636541bccd20d4cdd953d6b/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string123 = /88552e15e5ce836e9f7f1b12b55ca6b3805641d577fb71663d2c8fc5fb96ce47/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string124 = /8857efba9865de5690af4a3559f4839286cd2083f752ba93c30bd969c6636170/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string125 = /89d3c1ac21486c9deb1a08ac10cc6b722a19801163dad4d8b57c1aa8a18f32b8/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string126 = /8a131449c4f5bffc5ae0cda597df9d17a3dff1d02422c890622c0359ee0a03f1/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string127 = /8c7511cc6dae84071080a37c2842782cc0635f8d32301afebdc818a392a58bc3/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string128 = /90487bd2731d62d51c5bda9ea313fe915fb6ce31fc2c5f54622d780d924da26e/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string129 = /96c7a830d1ec55b1db8892e1d452394cd2a5eb2549003d4428b5d52774637e94/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string130 = /9abd6408e999901f0b7504eb679d0403f49589b7ecaaa5588923daa0bb22f186/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string131 = /9acdf1fd60fb9b5185fab1f18b843757f05f34f73ce947b71498d494a9e30843/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string132 = /9c6804a10a191fe49061ca8022394c3a44fba75e20aa0c1fbf79a07e01f28df5/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string133 = /9d780803519141fc8c14c067688184d7df094190cf74825b6ea6651e7ccd911b/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string134 = /9f6a38018fe8228de57605c35bb927d39418c7793bb935ff0ab5022424d9774a/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string135 = /a1be92f17090edca27bbb0af8e9ac44b97d7a2dd15b66d09e1a6a6b237ace336/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string136 = /a1ce03c2907bdfc7be8ab37b967961a4adb4c2764bbb0f42afea773d1f89f666/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string137 = /a9b13111606ca8ed948030515217c0e1af7cf2af2af8eb034999ff9e3f071b24/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string138 = /apt\sinstall\sgsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string139 = /apt\-get\sinstall\sgsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string140 = /b035dfbf2f3125fbf0d00f86158efbc4a7c7715f03e4d7bcf634dfd16888e965/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string141 = /b3ed38872b50a110a8704d1d2eb4e6e47ed6f2998d1bd08b712f840cc3a4643a/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string142 = /b6e5d9d7d95caf2550fecebcfe6f7c54f1779c6a65547ef342f76446dcbd6c1d/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string143 = /b7890a15dadef8cdedd6580aed94ca26df6ec0eddb009176dba1eef8941ff6e6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string144 = /b938ac4eb603113d3617ddcfeb8fbb32a6bbe54b1419482966b41ee8b1dc05b9/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string145 = /bc7229c619a3af7fd330588286b4e48e7804b1c03427ef9e8bb3b7e2eb0318ce/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string146 = /bd0f5440775fe02946ffc659425427ef167a1dd6d2993606d4376422f8d33bc4/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string147 = /c08ba6e45d3859ecb3cd5df132fb04dcd86913afce15057de03bba9d256de4ef/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string148 = /c2e755a58685ea4f356c897fdc0c9420579f6eae48ac6f27307e8a8b73500cb6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string149 = /c4da631e510a57e39a6e9021a1d3f1d563f59f351bdd84b46e48a0e27e6b9cbb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string150 = /c74f294042ccfc39dec052d9871e6bbd4e69b019a353f6e02947303adeac3794/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string151 = /cc0ced090edf59964428ab7b16b9cf8ce57b8ee21e999ac05e7f4d5d52b5470c/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string152 = /cd672b609691c61005f4c69233abbce538d334db30e809150f8087b7735bfd2e/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string153 = /ce7979010bdb291a0a1884e00e238d9fc3bc27ec7a1d1093be273c22e865f676/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string154 = /cfa25f5e4321a86b2c4f646a63345fb6ac46a7089886354ad82653a47e55be51/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string155 = /cfcad25ab252fbff7fc8a7bbac67915dfce5f76b5738f894fa13afbd5d60a5de/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string156 = /curl\s\-fsSL\shttps\:\/\/gsocket\.io\/x/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string157 = /curl\s\-fsSL\shttps\:\/\/tiny\.cc\/gsinst/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string158 = /d24fe924f62a3bb95319812d67dbdb7e375d60f7baa933eab82070b3c4a11a77/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string159 = /d325c92a9bba538fdbb1c054584ffd0672debaef935dfb27e9d0a6b67649d369/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string160 = /d69430717f07c774cdb8ea58b32b066e99dbf3cbc046e876b8ea73c20a3a6507/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string161 = /d700c8a3a4ecbb1e547b3c14a5a2a3605cabbabc8350284e923982809945694d/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string162 = /d748b4244f359f0d9c46860ea8918940c8cd05e4a65c3ae5b99208d719a3a9c1/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string163 = /d84d9d935f9f3392934ff2613e47032d3120f7c0ac4278a1e88bec65c5316a53/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string164 = /db17fa0b10c60bd01a60f64cf436586c9c6708ad64a1dce8350e13689336d67f/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string165 = /dd226a8ba33f50cd9ca4fedcec4df5c29e6b9841cb8cf2ab2d940bdef8a0a403/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string166 = /de74cc01088879ddf3f7c392345e9229490e06f0cc03c52102b0e94b79c01cfc/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string167 = /dfd2e8d943aab32e5988a886e6ed0a3bb36b5f5c3959fa3fb1281b6f524b16bb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string168 = /e05dfa6b3fc5b59044f4b18ba455d751c5a18948d1d0a032d3a11fb753659faa/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string169 = /e417c3eb936ec35eb80f7cab07aaba0c051f3385d8262eaa93e5e59f52cb60e7/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string170 = /e660765bee5e704c8f15d6a20c14d720c0aea5382fd21123974df9435a3b7bad/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string171 = /e66ba30f8c2e47462d60db7d5bdcb9465fa63c7115a2287d68f57d191ada1b6e/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string172 = /e74e119f6c9d89e2419518395abc0bb44008928d3748b60ea7d02e70b757a75a/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string173 = /e897d08460dbb646108b17a32455d9be51487bee26b48dfef992b7f246d54f1d/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string174 = /e8bcea5769f7121a256a8d690d1eeae2a6040af90d7d97fccfc0379c241df060/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string175 = /eb11e2e1f6611560c9822ca53a829028642a676c2d03bbf86c57e4b41fdcff9e/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string176 = /ec7ac72aea879c8a68fe5cbd38f8be5f37c7b3ee99ca67481331b8eba84f7726/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string177 = /ececdc677eaf4bf46268f4839d825090b16a40d37803c38600bf52bc79e1a363/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string178 = /ef8eb970940d435e07001fccf2ac210f539a9bb09ea1ef146c5f6ff4cc15a402/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string179 = /eff4aa3e27c98422705a19de82c1386d11b9559ded06eed46c26ab82860c0a81/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string180 = /f18bc0dae72814ff2e076c2b61846a35d00575c4e1554f74a4a70a036a15f9c5/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string181 = /f32a57e81fc9d08ca1412e932e8701a45ed35b0213c0da78bee8e65a1c6942e9/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string182 = /f94c9642833e1efd81b07dcb06bf653f61937ae8b7baf69b3731ac1132a66d52/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string183 = /fc0e69e5c2f4ed4cfb830ebb66ba54a86ce95a114603a5fffa42cea8caf3e864/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string184 = /fcea3e6443289fde4faa10d9d892ce4f0c23f90913dbfde6c9f60c825f92150c/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string185 = /fd57273dcd84084b20ad214de3b38c4e5a3f506da7810574d4a68dcdd63176cb/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string186 = /fecf1da09ddb7a5f5ab7cc20c6d542be33193cbc30e5c8c3dd877cee6a682063/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string187 = /GS_SO_TOR_DOMAIN/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string188 = /gs\-full\-pipe\s\-s\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string189 = /gs\-netcat\s\-/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string190 = /gs\-netcat\s.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string191 = /gs\-netcat_freebsd\-x86_64/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string192 = /gs\-netcat_linux\-aarch64/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string193 = /gs\-netcat_linux\-arm/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string194 = /gs\-netcat_linux\-armhf/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string195 = /gs\-netcat_linux\-armv6/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string196 = /gs\-netcat_linux\-armv7l/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string197 = /gs\-netcat_linux\-i686/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string198 = /gs\-netcat_linux\-mips32/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string199 = /gs\-netcat_linux\-mips64/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string200 = /gs\-netcat_linux\-mipsel/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string201 = /gs\-netcat_linux\-x86_64/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string202 = /gs\-netcat_macOS/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string203 = /gs\-netcat_openbsd\-x86_64/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string204 = /gsocket\s\/usr\/sbin\/sshd/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string205 = /gsocket\s\-k\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string206 = /gsocket\sopenvpn\s\-\-/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string207 = /gsocket\sssh\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string208 = /gsocket\.io\/deploy/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string209 = /gsocket\/gsocket\.h/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string210 = /gsocket_macOS\.tar\.gz/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string211 = /GSOCKET_SECRET/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string212 = /GSOCKET_SOCKS_IP/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string213 = /GSOCKET_SOCKS_PORT/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string214 = /gsocket\-relay\/monitor\// nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string215 = /gs\-sftp\s\-l/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string216 = /gs\-sftp\s\-s\sthctestserver/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string217 = /hackerschoice\/gsocket/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string218 = /https\:\/\/gsocket\.io\/install\.sh/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string219 = /Installing\ssystemwide\sremote\saccess\spermanentally/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string220 = /Join\sus\son\sTelegram\s\-\shttps\:\/\/t\.me\/thcorg/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string221 = /Running\:\snetcat\s/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string222 = /socat\s\-\sTCP_LISTEN\:31337/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string223 = /TCP\:gsocket\:31337/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string224 = /Testing\sGlobal\sSocket\sRelay\sNetwork/ nocase ascii wide
        // Description: The Global Socket Tookit allows two users behind NAT/Firewall to establish a TCP connection with each other. Securely.
        // Reference: https://github.com/hackerschoice/gsocket
        $string225 = /wget\s\-qO\-\sgsocket\.io/ nocase ascii wide

    condition:
        any of them
}
