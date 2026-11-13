// SSDT-CSTFix — _CST override for the Lenovo 83GX RPL-P (cachyOS/Linux ACPI dump).
//
// The firmware's real _CST (ssdt20 PmRef/Cpu0Cst, mirrored by 63 aliases in
// ssdt27 for \_SB.PR01..PR3F that call \_SB.PR00._CST) reads C-state policy
// from the PCH NVS at 0x44925000. Unpopulated (CFGD=0) it returns C1 ONLY —
// which is exactly the package PC2 floor measured on macOS (PC3+ = 0.00% in
// every powermetrics capture). Linux boots with the NVS populated
// (CFGD=0x4828, C7MW=0x21, CDMW=0x60) and idles in MWAIT 0x21 + 0x60 (core
// C2/C6), which is what reaches package PC3/PC6/PC8/PC10 at 2.25 W.
//
// This block redefines \_SB.PR00._CST with the Linux-populated state list,
// sanitized for XNU: non-zero latency and power on every entry (the firmware
// variants carry 0/0, which macOS rejects). The ssdt27 aliases resolve to
// this method, so every processor object picks it up.
DefinitionBlock ("", "SSDT", 2, "CORP", "CSTFix", 0x00003001)
{
    External (\_SB.PR00, ProcessorObj)

    Scope (\_SB.PR00)
    {
        Name (PKG0, Package (0x04)
        {
            // C1: FFH MWAIT 0x00 (matches acpiexec output on both states)
            ResourceTemplate ()
            {
                Register (FFixedHW,
                    0x01,               // Bit Width
                    0x02,               // Bit Offset
                    0x00,               // Address = MWAIT hint 0x00
                    0x01)               // Access Size
            },
            One,                           // Type    = 1 (C1)
            One,                           // Latency = 1 us
            0x03E8                         // Power   = 1000 mW
        })

        Name (PKG1, Package (0x04)
        {
            // C2: FFH MWAIT 0x21 (Linux C2_ACPI, latency 127 us)
            ResourceTemplate ()
            {
                Register (FFixedHW,
                    0x01,
                    0x02,
                    0x21,               // MWAIT hint 0x21
                    0x01)
            },
            0x02,                          // Type    = 2 (C2)
            127,                           // Latency = 127 us
            0x00C8                         // Power   = 200 mW
        })

        Name (PKG2, Package (0x04)
        {
            // C3: FFH MWAIT 0x60 (Linux C3_ACPI = core C6, latency 1048 us).
            // Latency/power sanitized from 0/0: XNU skips zero-valued entries.
            ResourceTemplate ()
            {
                Register (FFixedHW,
                    0x01,
                    0x02,
                    0x60,               // MWAIT hint 0x60
                    0x01)
            },
            0x03,                          // Type    = 3 (C3)
            1048,                          // Latency = 1048 us
            0x0064                         // Power   = 100 mW
        })

        Method (XCST, 0, Serialized)
        {
            Return (Package (0x04)
            {
                0x03,                      // 3 entries
                PKG0,
                PKG1,
                PKG2
            })
        }
    }
}
