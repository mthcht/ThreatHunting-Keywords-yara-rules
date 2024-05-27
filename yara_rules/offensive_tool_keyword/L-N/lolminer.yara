rule lolminer
{
    meta:
        description = "Detection patterns for the tool 'lolminer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "lolminer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string1 = /\.2miners\.com/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string2 = /\.herominers\.com/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string3 = /\/lolminer\.exe/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string4 = /\/lolMiner_v.{0,1000}_Win64\.zip/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string5 = /\/lolMinerGUI\.exe/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string6 = /\\dual_mine_etc_aleph_herominer\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string7 = /\\dual_mine_etc_aleph_lhr_admin\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string8 = /\\dual_mine_etc_aleph_woolypooly\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string9 = /\\dual_mine_ethw_aleph_herominer\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string10 = /\\dual_mine_ethw_aleph_lhr_admin\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string11 = /\\dual_mine_ethw_aleph_woolypooly\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string12 = /\\dual_mine_rth_aleph\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string13 = /\\dual_mine_rth_kls\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string14 = /\\dual_mine_rth_rxd\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string15 = /\\lolMiner\.cfg/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string16 = /\\lolminer\.exe/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string17 = /\\lolMinerGUI\.cpp/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string18 = /\\lolMinerGUI\.pdb/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string19 = /\\mine_aleph\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string20 = /\\mine_beam\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string21 = /\\mine_bittube\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string22 = /\\mine_btg\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string23 = /\\mine_cortex\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string24 = /\\mine_ergo\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string25 = /\\mine_etc\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string26 = /\\mine_eth\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string27 = /\\mine_eth_lhr_admin\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string28 = /\\mine_ethw\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string29 = /\\mine_ethw_lhr_admin\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string30 = /\\mine_flux\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string31 = /\\mine_flux_admin\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string32 = /\\mine_gram\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string33 = /\\mine_grin_32\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string34 = /\\mine_ironfish\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string35 = /\\mine_ironfish_gram\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string36 = /\\mine_karlsen\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string37 = /\\mine_nexa\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string38 = /\\mine_nexa_with_oc\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string39 = /\\mine_pyrin\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string40 = /\\mine_radiant\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string41 = /\\mine_rth\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string42 = /\\mine_ubq\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string43 = /\\mine_zcl\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string44 = /\\triple_mine_zil_etc_aleph\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string45 = /\\triple_mine_zil_ethw_aleph\.bat/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string46 = /00f30b9daeee37dd8ae0c6e0f61b14b3de19d45f504ba5d288f2a45dfe3cc652/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string47 = /070f9bbe7bf3f68bca8bcc2b0baa1a6eadc0105e2e1766b06a0f5a912d12fcab/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string48 = /0f8b3d08754df255a2d275a9b27c2f324e86f73cf7c679c577b1551b6dad590e/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string49 = /115ac6d10a371a9f22cdf0190e84a5a4c4d5b4b625bf8d571d68f95b507424e5/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string50 = /263a97ae0cf8daefca89d894014060176d030af5b2e94cea2846af2e4c64c644/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string51 = /4059185741fed75ca2f3551cbcc522265ed3c63f15da6b12301a21668ff7c33d/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string52 = /43195f385c68a53280d094289acfe2730ed0c503053e704a33a563e0aa0825fe/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string53 = /447ea37d555fb32ea2957369ea1aeee31898a4e1f1783eb834dc9df2f469252e/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string54 = /451d10d93c241b86d688cba1b05c7b5ee74995b5b558e11a6a4b114d080f5dce/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string55 = /4a96ba27c260b02607556b05e93f631af307a6046a79936e8e229ecd84f12b7f/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string56 = /547b97d9bb9bfc6250599e19357911ab5ae3dde3ca5f0d49bea0e66e46799dfc/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string57 = /56888116d58c75328e0b32af2b26f98c1f79e6b513e436db51aa650efa55a60b/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string58 = /5e072a48d093df02065faaeee6bbc019e1e6c4ac85ae0b00726c5dc216886bb1/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string59 = /641867dbb57f198f42dc86ea0d27eaaab36190417ffc24e6a186c831a98c0051/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string60 = /6824586e095fec0e58ee872ecf5108b370bd8713987988510aacf3793cbe1114/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string61 = /73a1461ab0925ac9df52dca7f7b3b2c8e46f25e440228c17d2c95c430bf22e68/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string62 = /740879d5c5c757899862884c89b2d1386ff5b85a68d8d847201080f74201ed36/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string63 = /7419174a31b2ec7503765d473943459f5d3d959c0c69fa23da6f6f551e6464ce/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string64 = /7fa4e734f5dddd6e3e912dda25a744ffa615735a9e65ac1319412cd4fb91d1cc/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string65 = /8a01a909a9fbaeb9d1061774811d0d2b165ff7dd199fea5543a75773bd5b13a7/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string66 = /9680bea8301be835e4f7e35220c4dfbb48ecf51b3fb9d0405c7fa8e8abfab28e/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string67 = /96aaf948fb2eef6f40f56164125e6dcd819e09c444f569c1a2a7df1ec0b009d7/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string68 = /a0767e6ca9109d8a0e82ac8abe1a1971e03de8d734905a09854244e9d316f73a/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string69 = /a5e057e11af84fb4e663c3d1f580dc6df73c2cca29bb63008717590f0d53883f/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string70 = /aa0daaab2228d5befff8982d5b44267a0272e971799dd77225449e005ec5d83e/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string71 = /aeec0f065823849ebb2ded6654d59526ee8b73520117bd033a19e011c9455248/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string72 = /bc0ff8a55724a6ac40a71ca1b0072e40c34e80c13c26688860fdf3c4e5309f25/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string73 = /beb128325351c7c87a1928ec9cb98e595f39b3da1a105bf229b04548644a3957/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string74 = /bef1d97b5fa30aea0ddffcc7275d34f13c54bf8b812326a37e958a314968d3af/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string75 = /ca39b6544676022075793b762288a2d13bd3db50d4ce983c624931639dbb75c6/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string76 = /df117b05c21cd8ef0c6c4d85290d81532838e4645677bdb2955a968eba9da682/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string77 = /df3adfbca15691d22d9dd17b3247e1ef434b0b85863ce1e6900565cdbf8b1cd4/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string78 = /e1a58a89aa3d31654d9496700ebbfb27e2914cce90d78425864b948097c35090/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string79 = /e5d6d5fe4ebbae6ba141cf25faa3f05e915916b0980b90297a8b2e59b2312bb8/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string80 = /e7b3627d04efe0c3b201656b9bda35df126551dfb3eb47b506e1238bcc4b2ffe/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string81 = /eb93d18ebddbcc79c037708558cbf1295b85a75230ba1690f07d287433d48fd1/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string82 = /ef3eb0e2dc2a3be441eef0bdc97eb16eb311187a6387f3e757eb0569795dcc41/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string83 = /eu1\-etc\.ethermine\.org/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string84 = /europe\.equihash\-hub\.miningpoolhub\.com/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string85 = /f67880e200d99b83404108e9a563c7f97eda8ac8c3fff08dc065d8734cfa57a1/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string86 = /fb3fc9cf96316c4e18a633564cfc32f0345a14ec544715fdeb23a8e773d7d46b/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string87 = /fdad34a59a97f03cc8b8da455730e1bf8557c95dcf866b38971afa75e0c34026/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string88 = /https\:\/\/github\.com\/Lolliedieb\/lolMiner\-releases\/releases\/download\// nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string89 = /Running\slolMiner\sfrom\s/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string90 = /ubiq\-eu1\.picopool\.org/ nocase ascii wide
        // Description: NVIDIA+AMD GPU Miner
        // Reference: https://github.com/Lolliedieb/lolMiner-releases
        $string91 = /WALLET\=.{0,1000}\.lolMinerWorker/ nocase ascii wide

    condition:
        any of them
}
