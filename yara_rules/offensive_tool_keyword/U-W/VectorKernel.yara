rule VectorKernel
{
    meta:
        description = "Detection patterns for the tool 'VectorKernel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "VectorKernel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string1 = /\/VectorKernel\.git/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string2 = /\\\\Device\\\\StealToken/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string3 = /\\GetFullPrivs\\GetFullPrivs/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string4 = /\\GetFullPrivsDrv\.cpp/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string5 = /\\GetFullPrivsDrv\.exe/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string6 = /\\GetProcHandleDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string7 = /\\ProcProtectClient\.exe/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string8 = /\\QueryModuleClient\.exe/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string9 = /\\StealTokenClient\.exe/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string10 = /\\StealTokenDrv\.cpp/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string11 = /\\StealTokenDrv\.exe/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string12 = /02EF15C0\-BA19\-4115\-BB7F\-F5B04F7087FE/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string13 = /0C89EC7D\-AC60\-4591\-8F6B\-CB5F20EC0D8D/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string14 = /1250BAE1\-D26F\-4EF2\-9452\-9B5009568336/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string15 = /171A9A71\-EDEF\-4891\-9828\-44434A00585E/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string16 = /28F9E001\-67E0\-4200\-B120\-3021596689E9/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string17 = /2FB94059\-2D49\-4EEA\-AAF8\-7E89E249644B/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string18 = /3F0C3D9A\-CFB8\-4DB5\-8419\-1C28CBC8621D/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string19 = /3FBBC3DD\-39D9\-4D8C\-AF73\-EDC3D2849DEB/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string20 = /51E46096\-4A36\-4C7D\-9773\-BC28DBDC4FC6/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string21 = /56F981FD\-634A\-4656\-85A7\-5636658E1F94/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string22 = /628E42D5\-AE4F\-4CDD\-8D14\-DAB1A3697B62/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string23 = /9E5A6F99\-0A26\-4959\-847D\-A4221CF4441B/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string24 = /9EFFFF7A\-DC03\-4D52\-BB8F\-F0140FAD26E7/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string25 = /9FEA6712\-3880\-4E5F\-BD56\-8E58A4EBCCB4/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string26 = /A017568E\-B62E\-46B4\-9557\-15B278656365/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string27 = /AD0067D9\-4AF6\-47C2\-B0C3\-D768A9624002/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string28 = /B9635D08\-2BB2\-404B\-92B7\-6A4981CB34F3/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string29 = /BDED2735\-F9E4\-4B2E\-9636\-4EEDD78FC720/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string30 = /BlockNewProcClient\.exe\s\-/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string31 = /BlockNewProcDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string32 = /C7F1F871\-8045\-4414\-9DC3\-20F8AA42B4A1/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string33 = /C8C12FA3\-717F\-4D35\-B8B3\-2E7F7A124E7C/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string34 = /CreateTokenClient\.exe\s/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string35 = /CreateTokenDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string36 = /D19BD978\-267A\-4BF0\-85CC\-851E280FF4C2/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string37 = /daem0nc0re\/VectorKernel/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string38 = /FC5A1C5A\-65B4\-452A\-AA4E\-E6DCF1FA04FB/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string39 = /GetFullPrivsClient\.exe/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string40 = /GetFullPrivsDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string41 = /GetProcHandleClient\.exe\s/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string42 = /InjectLibraryClient\.exe\s\-/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string43 = /InjectLibraryDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string44 = /ModHideDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string45 = /ProcHideClient\.exe\s\-/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string46 = /ProcHideDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string47 = /ProcProtectClient\.exe\s/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string48 = /StealTokenClient\.exe\s/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string49 = /StealTokenClient\\StealTokenClient\.cs/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string50 = /StealTokenDrv_x64\.sys/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string51 = /VectorKernel\\BlockNewProc/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string52 = /VectorKernel\\CreateToken/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string53 = /VectorKernel\\ModHide/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string54 = /VectorKernel\\StealToken/ nocase ascii wide
        // Description: PoCs for Kernelmode rootkit techniques research.
        // Reference: https://github.com/daem0nc0re/VectorKernel/
        $string55 = /VectorKernel\-main\.zip/ nocase ascii wide

    condition:
        any of them
}
