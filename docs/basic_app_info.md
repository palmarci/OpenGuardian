# The (Guardian) App

The app is built on Flutter and runs on the Dart VM. It has two native ELF binary components: one is called the SCP (likely standing for Security ? Provider), and the other is the SAKE library, used for secure communication with the transmitter.

The app implements various security measures:

- White and blacklists for tested device models and Android versions.
- Root detection.
- SafetyNet checks.
- Database encryption (via SQLCipher).

If the app is patched it will NOT be able to receive the SAKE keys, because PlayIntegrity will detect it but MITM is still possible for login and the "Teneo secure communications" (after some Frida scripts).