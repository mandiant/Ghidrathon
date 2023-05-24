# Ghidrathon

[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

Ghidrathon is a Ghidra extension that adds Python 3 scripting capabilities to Ghidra. Why? Ghidra natively supports scripting in Java and Jython. Unfortunately many open-source analysis tools, like [capa](https://github.com/mandiant/capa), [Unicorn Engine](https://github.com/unicorn-engine/unicorn), [angr](https://github.com/angr/angr), etc., are written in Python 3 making it difficult, and in some cases, impossible to use these tools in Ghidra. More so the security community has released several great plugins for other SRE frameworks like IDA Pro and Binary Ninja, but again, because many of these plugins use Python 3 it is difficult to port them to Ghidra. Ghidrathon helps you use existing and develop new Python 3 tooling in Ghidra and script Ghidra using modern Python in a way that tightly integrates with Ghidra's UI.

Check out:

- The overview in our first [Ghidrathon blog post](https://www.mandiant.com/resources/blog/ghidrathon-snaking-ghidra-python-3-scripting)

Ghidrathon replaces the existing Python 2 extension implemented via Jython. This includes the interactive interpreter window, integration with the Ghidra Script Manager, and script execution in Ghidra headless mode. 

## Python 3 Interpreter Window

The interpreter window provides interactive access to your Python 3 interpreter. Click "Window" and select "Ghidrathon" to open the interpreter window.

![example](./data/ghidrathon_interp.png)

## Ghidra Script Manager Integration

Ghidrathon integrates directly with the Ghidra Script Manager enabling you to create, edit, and execute Python 3 scripts within Ghidra. Click "Create New Script" and select "Python 3" to create a new Python 3 script. Click "Run Script" or "Run Editors's Script" to execute your Python 3 script and check the Ghidra Console window for script output.

For compatibility with existing Jython scripts, Ghidrathon scripts must end with the `.py3` extension. This only applies to the script itself - modules imported by the script should use the usual `.py` extension.

![example](./data/ghidrathon_script.png)

## Ghidra Headless Mode

Ghidrathon helps you execute Python 3 scripts in Ghidra headless mode. Execute the `analyzeHeadless` script located in your Ghidra installation folder, specify your Python 3 script, and check the console window for script output.

```
$ ~/ghidra/support/analyzeHeadless ~/dev/ghidra_projects testProject -import /tmp/test.elf -postScript ghidrathon_example.py3
openjdk version "17.0.7" 2023-04-18
[...]
INFO  SCRIPT: /home/user/.ghidra/.ghidra_10.3_PUBLIC/Extensions/Ghidrathon/ghidra_scripts/ghidrathon_example.py3 (HeadlessAnalyzer)  
Function FUN_00400380 @ 0x400380: 1 blocks, 2 instructions
Function __libc_init @ 0x400390: 1 blocks, 1 instructions
Function __cxa_atexit @ 0x4003a0: 1 blocks, 1 instructions
Function puts @ 0x4003b0: 1 blocks, 1 instructions
Function __atexit_handler_wrapper @ 0x4003c0: 3 blocks, 4 instructions
Function _start @ 0x4003d0: 1 blocks, 16 instructions
Function atexit @ 0x400420: 1 blocks, 4 instructions
Function main @ 0x400436: 1 blocks, 6 instructions
Function __libc_init @ 0x403000: 0 blocks, 0 instructions
Function __cxa_atexit @ 0x403008: 0 blocks, 0 instructions
Function puts @ 0x403010: 0 blocks, 0 instructions
INFO  ANALYZING changes made by post scripts: /tmp/test.elf (HeadlessAnalyzer)  
INFO  REPORT: Post-analysis succeeded for file: /tmp/test.elf (HeadlessAnalyzer)  
INFO  REPORT: Save succeeded for: /test.elf (testProject:/test.elf) (HeadlessAnalyzer)  
INFO  REPORT: Import succeeded (HeadlessAnalyzer)  
```

For more information on running Ghidra in headless mode check out `<ghidra_install>/support/analyzeHeadlessREADME.html`.

## Third-Party Python Modules

One of our biggest motivations in developing Ghidrathon was to enable use of third-party Python 3 modules in Ghidra. You can install a module and start using it inside Ghidra just as you would a typical Python setup. This also applies to modules you have previously installed. For example, we can install and use Unicorn to emulate ARM code inside Ghidra.

![example](./data/ghidrathon_unicorn.png)

## How does it work?

Ghidrathon links your local Python installation to Ghidra using the open-source project [Jep](https://github.com/ninia/jep). Essentially your local Python interpreter is running inside Ghidra with access to all your Python packages **and** the standard Ghidra scripting API. Ghidrathon also works with Python virtual environments helping you create, isolate, and manage packages you may only want installed for use in Ghidra. Because Ghidrathon uses your local Python installation you have control over the Python version and environment running inside Ghidra.

For more information on how Jep works to embed Python in Java see their documentation [here](https://github.com/ninia/jep/wiki/How-Jep-Works).

## OS Support

Ghidrathon supports the following operating systems:

* Linux
* Windows
* macOS (x86_64)

## Requirements

The following tools are needed to build, install, and run Ghidrathon:

Tool | Version |Source |
|---|---|---|
| Ghidra | `>= 10.2` | https://ghidra-sre.org |
| Jep | `>= 4.1.1` | https://github.com/ninia/jep |
| Gradle | `>= 7.3` | https://gradle.org/releases |
| Python | `>= 3.7` | https://www.python.org/downloads |

Note: Ghidra >= 10.2 requires [JDK 17 64-bit](https://adoptium.net/temurin/releases/).

## Python Virtual Environments

Ghidrathon supports Python virtual environments. To use a Python virtual environment, simply build Ghidrathon inside your virtual environment **and** execute Ghidra inside the **same** virtual environment.

## Building Ghidrathon

**Note:** Review [Python Virtual Environments](#python-virtual-environments) before building if you would like to use a Python virtual environment for Ghidrathon.

**Note**: Building Ghidrathon requires building Jep. If you are running Windows, this requires installing the Microsoft C++ Build Tools found [here](https://visualstudio.microsoft.com/visual-cpp-build-tools/). See Jep's documentation [here](https://github.com/ninia/jep/wiki/Windows) for more information on installing Jep on Windows.

Use the following steps to build Ghidrathon for your environment:

* Install Ghidra using the documentation [here](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/InstallationGuide.html#InstallationNotes)
* Install Gradle from [here](https://gradle.org/releases)
* Download the latest Ghidrathon source release from [here](https://github.com/mandiant/Ghidrathon/releases)
* Run the following command from the Ghidrathon source directory:
    * **Note:** Ghidrathon defaults to the Python binary found in your path. You can specify a different Python binary by adding the optional argument `-PPYTHON_BIN=<absolute path to Python binary>` to the command below
    * **Note:** you may optionally set an environment variable named `GHIDRA_INSTALL_DIR` instead of specifying `-PGHIDRA_INSTALL_DIR`

```
$ gradle -PGHIDRA_INSTALL_DIR=<absolute path to Ghidra install>
```

This command installs Jep, configures Ghidrathon with the necessary Jep binaries, and builds Ghidrathon. If successful, you will find a new directory in your Ghidrathon source directory named `dist` containing your Ghidrathon extension (`.zip`). Please open a new issue if you experience any issues building Ghidrathon.

## Installing Ghidrathon

Use the following steps to install your Ghidrathon extension in Ghidra:

* Start Ghidra
* Navigate to `File > Install Extensions...`
* Click the green `+` button
* Navigate to your Ghidrathon extension built earlier (`.zip`)
* Click `Ok`
* Restart Ghidra

**OR**

You can extract your Ghidrathon extension (`.zip`) directly to `<absolute path to Ghidra install>\Ghidra\Extensions` and Ghidra will prompt you to configure Ghidrathon the next time it is started.

## Using Ghidrathon

See [Python 3 Interpreter Window](#python-3-interpreter-window), [Ghidra Script Manager Integration](#ghidra-script-manager-integration), and [Ghidra Headless Mode](#ghidra-headless-mode) for more information about using Ghidrathon.

## Considerations

Ghidrathon uses the open-source library [Jep](https://github.com/ninia/jep) which uses the Java Native Interface (JNI) to embed Python in the JVM. The Ghidra developers advise against JNI in Ghidra for reasons discussed [here](https://github.com/NationalSecurityAgency/ghidra/issues/175).
