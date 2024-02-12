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

Warning for Windows 2019 : If you get a connection issue, you'll need to import the certificate manually (do not hesitate to contact us if needed)

### For Linux Enthusiasts
1. **Configuration Setup:** As with the Windows setup, first, configure your username, password, and warehouse ID in the `CellaDispatcher.ini` file.
2. **Execution:** To kickstart the program, simply run it via Python using the following command:
   ```bash
   python3 CellaDispatcher.py
   ```

## License
Cella dispatcher is released under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version (GPL-3+).

See the [LICENSE.md](LICENSE.md) file for a full copy of the license.
