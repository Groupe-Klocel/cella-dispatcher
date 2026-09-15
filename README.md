# Cella Dispatcher: Streamlining Your Warehouse Operations

Cella Dispatcher is a versatile, cross-platform tool seamlessly integrated with [`CELLA WMS`](https://github.com/Groupe-Klocel/cella-frontend). It empowers you to effortlessly execute warehouse actions, such as automating document printing, directly from your operational hub.

## Getting Started

### For Windows Users
1. **Download the Latest Package:** Obtain the latest package and place all its files in a convenient folder where you intend to run the application.
2. **Configuration Setup:** To personalize your experience, input your username, password, and warehouse ID in the `CellaDispatcher.ini` file.
3. **Installation as a Windows Service:** With administrator privileges, execute the following command in your terminal:
   ```bash
   CellaDispatcher.exe install
   ```
   This action will create a Windows service aptly named `Cella Dispatcher Service`, which you can manage through the Windows Services application.

Warning for Windows Server 2019: If you encounter TLS/SSL connection errors when Cella Dispatcher connects to CELLA WMS (for example, certificate or trust-related errors), you may need to manually import the relevant server or corporate CA certificate into the Windows certificate store (Local Computer > Trusted Root Certification Authorities). Refer to Microsoft's documentation on managing certificates in MMC, or contact us if you need assistance.

### For Linux Enthusiasts
1. **Configuration Setup:** As with the Windows setup, first, configure your username, password, and warehouse ID in the `CellaDispatcher.ini` file.
2. **Execution:** To kickstart the program, simply run it via Python using the following command:
   ```bash
   python3 CellaDispatcher.py
   ```

## Printing PDF documents on Windows

PDF documents are printed with the bundled [SumatraPDF](https://www.sumatrapdfreader.org) (`src/SumatraPDF.exe`). Without settings, SumatraPDF shrinks the page to the paper and **turns any page wider than tall by 90 degrees** to match a printer configured in portrait mode. This is right for an A4 landscape report, but wrong for a label designed wider than tall (a 51 x 31 mm barcode label, a 6 x 4 inch location label): the label comes out sideways and reduced.

The optional `[PRINT_SETTINGS]` section of `CellaDispatcher.ini` forwards SumatraPDF `-print-settings` per printer:

```ini
[PRINT_SETTINGS]
; default for every printer without a line of its own, empty keeps the SumatraPDF defaults
*=
; label printers: never turn the page
ZEBRA39=disable-auto-rotation
Returns printer=disable-auto-rotation,noscale
```

- Keys are the printer names sent by CELLA (case insensitive); `*` applies to every printer without a line of its own. A printer with an empty line keeps the SumatraPDF defaults even when `*` is set.
- Several settings are separated by commas. Useful values: `disable-auto-rotation`, `noscale`, `shrink` (default), `fit`, `portrait`, `landscape`, `paper=<name>`, `bin=<name>`, `color`, `monochrome`, `duplex`, `simplex`. Unknown values are ignored by SumatraPDF.
- `disable-auto-rotation` needs SumatraPDF 3.5 or newer: older versions (such as 3.4.6) silently ignore it and keep turning the page. The bundled `src/SumatraPDF.exe` is version 3.6.1.
- ZPL documents are sent raw to the printer and are not affected. Printing on Linux goes through CUPS and is not affected either.

## License
Cella dispatcher is released under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version (GPL-3+).

See the [LICENSE.md](LICENSE.md) file for a full copy of the license.
