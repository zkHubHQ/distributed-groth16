
## Development Environment Setup for Rust and C on Ubuntu/Debian Linux

### Basic Setup

1. **Update System Packages**
   ```
   sudo apt update
   sudo apt upgrade -y
   ```

### Installing Rust

2. **Install Rust (using rustup)**
   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   ```
   - Follow the on-screen instructions to complete the installation.
   - After installation, run the following to configure your current shell.
   ```
   source $HOME/.cargo/env
   ```

### Installing C Development Tools

3. **Install build-essential (includes GCC/G++, make, etc.)**
   ```
   sudo apt install build-essential -y
   ```

### Additional Tools and Libraries

4. **Install Git**
   ```
   sudo apt install git -y
   ```

5. **Install Additional Libraries (if needed)**
   - For specific libraries your C or Rust projects might depend on, you can use `apt` to install them. For example, to install the OpenSSL library:
   ```
   sudo apt install libssl-dev -y
   ```

6. **Install Debugging Tools**
   ```
   sudo apt install gdb -y
   sudo apt install htop
   ```

7. **Install Package Manager for C (Optional)**
   - While not as common in C as in other languages, package managers like `conan` or `vcpkg` can be useful.
   - For `conan`:
     ```
     sudo apt install python-pip -y
     pip install conan
     ```
   - For `vcpkg`:
     - You would need to clone the `vcpkg` repository and run its bootstrap script. Instructions can be found on the [vcpkg GitHub page](https://github.com/microsoft/vcpkg).

### Setting up a Code Editor

8. **Installing a Code Editor (Optional)**
   - If you plan to code directly on the VM, you might want to install a text editor. Common choices are `vim`, `nano`, or `emacs`.
   - For `vim`:
     ```
     sudo apt install vim -y
     ```
   - For `nano`:
     ```
     sudo apt install nano -y
     ```
   - For `emacs`:
     ```
     sudo apt install emacs -y
     ```

### Post-Installation

9. **Verify Installations**
   - After installation, verify that the installations are successful.
   - For Rust:
     ```
     rustc --version
     ```
   - For GCC (C compiler):
     ```
     gcc --version
     ```
   - For Git:
     ```
     git --version
     ```

10. ** Setup Git **
   - Add the git config for name and aliases:
   ```
   git config --global user.name "Saurabh Chalke"
   git config --global user.email "saurabhchalke@gmail.com"
   ```
   - Create ssh key:
   ```
   ssh-keygen -t ed25519 -C "saurabhchalke@gmail.com"
   ```
   - Add the key in Github
   - Start the SSH Agent and add it to ~/.bashrc:
   ```
   eval "$(ssh-agent -s)"
   ssh-add ~/.ssh/id_ed25519
   ```