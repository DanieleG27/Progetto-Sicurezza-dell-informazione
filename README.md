# Java Cryptography & Security Analysis

A comprehensive implementation and vulnerability analysis of modern cryptographic primitives. This project explores the practical application of symmetric and asymmetric encryption while documenting common implementation pitfalls that compromise system security.

##  Overview
The goal of this project is to bridge the gap between theoretical cryptography and secure software development. By implementing standard algorithms in Java, I analyzed how improper parameter selection (e.g., static IVs, weak key lengths) leads to critical vulnerabilities.

##  Implemented Algorithms
- **Symmetric Encryption:** - **AES** (Modes: ECB, CBC, GCM)
  - **ChaCha20**
- **Asymmetric Encryption:** - **RSA** (Analysis of variable key lengths)
- **Security Testing:** Custom wrappers and test suites for vulnerability simulation.

##  Key Vulnerability Analyses
The project includes practical demonstrations of:
* **Initialization Vector (IV) Misuse:** Impact of static or predictable IVs in CBC and GCM modes.
* **Weak Key Lengths:** Demonstration of why RSA-512 is no longer secure.
* **Mode Pitfalls:** Why AES-ECB fails to provide semantic security for structured data (e.g., image encryption).
* **Padding & Parameters:** Documenting the risks of improper padding and hardcoded keys.

##  Tech Stack
* **Language:** Java
* **Libraries:** Java Cryptography Architecture (JCA / JCE)
* **Focus:** Security Auditing, Cryptographic Primitives, Implementation Best Practices
