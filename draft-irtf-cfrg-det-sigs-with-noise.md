---
title: "Hedged ECDSA and EdDSA Signatures"
category: info
updates: 6979, 8032

docname: draft-irtf-cfrg-det-sigs-with-noise-latest
submissiontype: IRTF  # also: "independent", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "cfrg/draft-irtf-cfrg-det-sigs-with-noise"
  latest: "https://cfrg.github.io/draft-irtf-cfrg-det-sigs-with-noise/draft-irtf-cfrg-det-sigs-with-noise.html"

author:
      -
        ins: J. Preuß Mattsson
        name: John Preuß Mattsson
        org: Ericsson
        email: john.mattsson@ericsson.com
      -
        ins: E. Thormarker
        name: Erik Thormarker
        org: Ericsson
        email: erik.thormarker@ericsson.com
      -
        ins: S. Ruohomaa
        name: Sini Ruohomaa
        org: Ericsson
        email: sini.ruohomaa@ericsson.com

normative:
  RFC2119:
  RFC6979:
  RFC8032:
  RFC8174:
  RFC8692:

  FIPS-186-5:
    target: https://doi.org/10.6028/NIST.FIPS.186-5
    title: Digital Signature Standard (DSS)
    seriesinfo: "NIST FIPS PUB 186-5"
    author:
      -
        ins: "National Institute of Standards and Technology, U.S. Department of Commerce"
    date: February 2023

  SHA3:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    seriesinfo: "NIST FIPS PUB 202"
    author:
      -
        ins: "National Institute of Standards and Technology (NIST)"
    date: August 2015

  KMAC:
    target: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
    title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash"
    seriesinfo: "NIST SP 800-185"
    author:
      -
        ins: "National Institute of Standards and Technology (NIST)"
    date: December 2016

informative:

  RFC8937:
  I-D.irtf-cfrg-frost:

  BSI:
    target: https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Zertifizierung/Interpretationen/AIS_46_ECCGuide_e_pdf.pdf?__blob=publicationFile
    title: "Minimum Requirements for Evaluating Side-Channel Attack Resistance of Elliptic Curve Implementations"
    author:
      -
        ins: "Bundesamt für Sicherheit in der Informationstechnik"
    date: November 2016

  Minerva19:
    target: https://minerva.crocs.fi.muni.cz/
    title: Minerva
    author:
      -
        ins: Centre for Research on Cryptography and Security (CRoCS)
    date: October 2019

  RowHammer14:
    target: https://users.ece.cmu.edu/~yoonguk/papers/kim-isca14.pdf
    title: "Flipping Bits in Memory Without Accessing Them: An Experimental Study of DRAM Disturbance Errors"
    author:
      -
        ins: Y. Kim
      -
        ins: R. Daly
      -
        ins: J. Kim
      -
        ins: C. Fallin
      -
        ins: J. Lee
      -
        ins: D. Lee
      -
        ins: C. Wilkerson
      -
        ins: K. Mutlu
    date: June 2014

  Plundervolt19:
    target: https://plundervolt.com/
    title: "How a little bit of undervolting can cause a lot of problems"
    author:
      -
        ins: K. Murdock
      -
        ins: D. Oswald
      -
        ins: F. Garcia
      -
        ins: J. Van Bulck
      -
        ins: D. Gruss
      -
        ins: F. Piessens
    date: December 2019

  TPM-Fail19:
    target: https://tpm.fail/
    title: "TPM-FAIL: TPM meets Timing and Lattice Attacks"
    author:
      -
        ins: D. Moghimi
      -
        ins: B. Sunar
      -
        ins: T. Eisenbarth
      -
        ins: N. Heninge
    date: October 2019

  XEdDSA:
    target: https://signal.org/docs/specifications/xeddsa/
    title: The XEdDSA and VXEdDSA Signature Schemes
    author:
      -
        ins: Signal
    date: October 2016

  libHydrogen:
    target: https://github.com/jedisct1/libhydrogen
    title: The Hydrogen library

  libSodium:
    target: https://github.com/jedisct1/libsodium
    title: The Sodium library

  Notice-186-5:
    target: https://www.federalregister.gov/documents/2019/10/31/2019-23742/request-for-comments-on-fips-186-5-and-sp-800-186
    title: Request for Comments on FIPS 186-5 and SP 800-186
    author:
      -
        ins: "National Institute of Standards and Technology (NIST)"
    date: October 2019

  Draft-204:
    target: https://csrc.nist.gov/pubs/fips/204/ipd
    title: FIPS PUB 204 (Draft)
    author:
      -
        ins: "National Institute of Standards and Technology (NIST)"
    date: August 2023

  SideChannel:
    target: https://arxiv.org/pdf/1611.03748.pdf
    title: "Systematic Classification of Side-Channel Attacks: A Case Study for Mobile Devices"
    author:
      -
        ins: R. Spreitzer
      -
        ins: V. Moonsamy
      -
        ins: T. Korak
      -
        ins: S. Mangard
    date: December 2017

  BCPST14:
    target: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.854.7836&rep=rep1&type=pdf
    title: "Online Template Attacks"
    author:
      -
        ins: L. Batina
      -
        ins: L. Chmielewski
      -
        ins: L. Papachristodoulou
      -
        ins: P. Schwabe
      -
        ins: M. Tunstall
    date: December 2014

  SH16:
    target: http://www.cs2.deib.polimi.it/slides_16/01_Seuschek_Deterministic_Signatures.pdf
    title: "A Cautionary Note: Side-Channel Leakage Implications of Deterministic Signature Schemes"
    author:
      -
        ins: H. Seuschek
      -
        ins: J. Heyszl
      -
        ins: F. De Santis
    date: January 2016

  BP16:
    target: https://link.springer.com/chapter/10.1007/978-3-319-44524-3_11
    title: A Note on Fault Attacks Against Deterministic Signature Schemes (Short Paper)
    author:
      -
        ins: A. Barenghi
      -
        ins: G. Pelosi
    date: September 2016

  RP17:
    target: https://romailler.ch/ddl/10.1109_FDTC.2017.12_eddsa.pdf
    title: Practical fault attack against the Ed25519 and EdDSA signature schemes
    author:
      -
        ins: Y. Romailler
      -
        ins: S. Pelissier
    date: September 2017

  ABFJLM17:
    target: https://eprint.iacr.org/2017/975
    title: Differential Attacks on Deterministic Signatures
    author:
      -
        ins: C. Ambrose
      -
        ins: J. Bos
      -
        ins: B. Fay
      -
        ins: M. Joye
      -
        ins: M. Lochter
      -
        ins: B. Murray
    date: October 2017

  SBBDS17:
    target: https://eprint.iacr.org/2017/985.pdf
    title: Breaking Ed25519 in WolfSSL
    author:
      -
        ins: N. Samwel
      -
        ins: L. Batina
      -
        ins: G. Bertoni
      -
        ins: J. Daemen
      -
        ins: R. Susella
    date: October 2017

  PSSLR17:
    target: https://eprint.iacr.org/2017/1014
    title: Attacking Deterministic Signature Schemes using Fault Attacks
    author:
      -
        ins: D. Poddebniak
      -
        ins: J. Somorovsky
      -
        ins: S. Schinzel
      -
        ins: M. Lochter
      -
        ins: P. Rösler
    date: October 2017

  SB18:
    target: https://nielssamwel.nl/papers/africacrypt2018_fault.pdf
    title: "Practical Fault Injection on Deterministic Signatures: The Case of EdDSA"
    author:
      -
        ins: N. Samwel
      -
        ins: L. Batina
    date: April 2018

  WPB19:
    target: https://eprint.iacr.org/2019/358.pdf
    title: "One trace is all it takes: Machine Learning-based
Side-channel Attack on EdDSA"
    author:
      -
        ins: L. Weissbart
      -
        ins: S. Picek
      -
        ins: L. Batina
    date: July 2019

  AOTZ19:
    target: https://eprint.iacr.org/2019/956
    title: Security of Hedged Fiat-Shamir Signatures under Fault Attacks
    author:
      -
        ins: D. Aranha
      -
        ins: C. Orlandi
      -
        ins: A. Takahashi
      -
        ins: G. Zaverucha
    date: September 2019

  FG19:
    target: https://eprint.iacr.org/2019/1053
    title: Modeling Memory Faults in Signature and Encryption Schemes
    author:
      -
        ins: M. Fischlin
      -
        ins: F. Günther
    date: September 2019

  Kampanakis16:
    target: https://blogs.cisco.com/security/fips-and-deterministic-ecdsa-achieving-robust-security-and-conformance
    title: "FIPS and Deterministic ECDSA: Achieving robust security and conformance"
    author:
      -
        ins: P. Kampanakis
    date: December 2016

  Langley13:
    target: https://www.imperialviolet.org/2013/06/15/suddendeathentropy.html
    title: "Sudden Death Entropy Failures"
    author:
      -
        ins: A. Langley
    date: June 2013

  OpenSSL13a:
    target: https://github.com/openssl/openssl/commit/8a99cb29d1f0013243a532bccc1dc70ed678eebe
    title: "Add secure DSA nonce flag"

  OpenSSL13b:
    target: https://github.com/openssl/openssl/commit/190c615d4398cc6c8b61eb7881d7409314529a75
    title: "Make `safe' (EC)DSA nonces the default"

  Comments-186-5:
    target: https://csrc.nist.gov/CSRC/media/Publications/fips/186/5/draft/documents/fips-186-5-draft-comments-received.pdf
    title: "Public Comments Received on Draft FIPS 186-5: Digital Signature Standards (DSS)"
    date: March 2021

  Bernstein19:
    target: https://blog.cr.yp.to/20191024-eddsa.html
    title: "Why EdDSA held up better than ECDSA against Minerva"
    author:
      -
        ins: D. Bernstein
    date: October 2019

  Bernstein14:
    target: https://blog.cr.yp.to/20140323-ecdsa.html
    title: "How to design an elliptic-curve signature system"
    author:
      -
        ins: D. Bernstein
    date: March 2014

  Cao20:
    target: https://eprint.iacr.org/2020/803
    title: "Lattice-based Fault Attacks on Deterministic Signature Schemes of ECDSA and EdDSA"
    author:
      -
        ins: Weiqiong Cao
      -
        ins: Hongsong Shi
      -
        ins: Hua Chen
      -
        ins: Jiazhe Chen
      -
        ins: Limin Fan
      -
        ins: Wenling Wu
    date: June 2020

  RFC8037:
  RFC8080:
  RFC8225:
  RFC8387:
  RFC8391:
  RFC8410:
  RFC8411:
  RFC8419:
  RFC8420:
  RFC8422:
  RFC8446:
  RFC8463:
  RFC8550:
  RFC8591:
  RFC8608:
  RFC8624:
  RFC8554:
  RFC9053:

--- abstract

Deterministic elliptic-curve signatures such as deterministic ECDSA and EdDSA have gained popularity over randomized ECDSA as their security does not depend on a source of high-quality randomness. Recent research, however, has found that implementations of these signature algorithms may be vulnerable to certain side-channel and fault injection attacks due to their deterministic nature. One countermeasure to such attacks is hedged signatures where the calculation of the per-message secret number includes both fresh randomness and the message. This document updates RFC 6979 and RFC 8032 to recommend constructions with additional randomness for deployments where side-channel attacks and fault injection attacks are a concern. The updates are invisible to the validator of the signature and compatible with existing ECDSA and EdDSA validators.

--- middle

# Introduction

In Elliptic-Curve Cryptography (ECC) signature algorithms, the per-message secret number has traditionally been generated from a random number generator (RNG). The security of such algorithms depends on the cryptographic quality of the random number generation and biases in the randomness may have catastrophic effects such as compromising private keys (see e.g., {{Bernstein19}}). Repeated per-message secret numbers have caused several severe security accidents in practice. As stated in {{RFC6979}}, the need for a cryptographically secure source of randomness is also a hindrance to deployment of randomized ECDSA {{FIPS-186-5}} in architectures where secure random number generation is challenging, in particular, embedded IoT systems and smartcards. {{ABFJLM17}} does however state that smartcards typically have a high-quality RNG on board, which makes it significantly easier and faster to use the RNG instead of doing a hash computation.

In deterministic ECC signatures schemes such as Deterministic Elliptic Curve Digital Signature Algorithm (ECDSA) {{RFC6979}}{{FIPS-186-5}} and Edwards-curve Digital Signature Algorithm (EdDSA) {{RFC8032}}, the per-message secret number is instead generated in a fully deterministic way as a function of the message and the private key. Except for key generation, the security of such deterministic signatures does not rely on a source of high-quality randomness. This makes verification of implementations easier. As they are presumed to be safer, deterministic signatures have gained popularity and are referenced and recommended by a large number of recent RFCs {{RFC8037}} {{RFC8080}} {{RFC8225}} {{RFC8387}} {{RFC8410}} {{RFC8411}} {{RFC8419}} {{RFC8420}} {{RFC8422}} {{RFC8446}} {{RFC8463}} {{RFC8550}} {{RFC8591}} {{RFC8608}} {{RFC8624}} {{RFC9053}}.

Side-channel attacks are potential attack vectors for implementations of cryptographic algorithms. Side-Channel attacks can in general be classified along three orthogonal axes: passive vs. active, physical vs. logical, and local vs. remote {{SideChannel}}. It has been demonstrated how side-channel attacks such as power analysis {{BCPST14}} and timing attacks {{Minerva19}} {{TPM-Fail19}} allow for practical recovery of the private key in some existing implementations of randomized ECDSA. {{BSI}} summarizes minimum requirements for evaluating side-channel attacks of elliptic curve implementations and writes that deterministic ECDSA and EdDSA requires extra care. The deterministic ECDSA specification {{RFC6979}} notes that the deterministic generation of per-message secret numbers may be useful to an attacker in some forms of side-channel attacks and as stated in {{Minerva19}}, deterministic signatures like {{RFC6979}} and {{RFC8032}} might help an attacker to reduce the noise in the side-channel when the same message it signed multiple times. Recent research {{SH16}} {{BP16}} {{RP17}} {{ABFJLM17}} {{SBBDS17}} {{PSSLR17}} {{SB18}} {{WPB19}} {{AOTZ19}} {{FG19}} have theoretically and experimentally analyzed the resistance of deterministic ECC signature algorithms against side-channel and fault injection attacks. The conclusions are that deterministic signature algorithms have theoretical weaknesses against certain instances of these types of attacks and that the attacks are practically feasibly in some environments. These types of attacks may be of particular concern for hardware implementations such as embedded IoT devices and smartcards where the adversary can be assumed to have access to the device to induce faults and measure its side-channels such as timing information, power consumption, electromagnetic leaks, or sound with low signal-to-noise ratio. A good summary of fault attacks in given by {{Cao20}}. See also the discussions and references in {{Comments-186-5}}.

Fault attacks may also be possible without physical access to the device. RowHammer {{RowHammer14}} showed how an attacker to induce DRAM bit-flips in memory areas the attacker should not have access to. Plundervolt {{Plundervolt19}} showed how an attacker with root access can use frequency and voltage scaling interfaces to induce faults that bypass even secure execution technologies. RowHammer can e.g., be used in operating systems with several processes or cloud scenarios with virtualized servers. Protocols like TLS, SSH, and IKEv2 that add a random number to the message to be signed mitigate some types of attacks {{PSSLR17}}.

Government agencies are clearly concerned about these attacks. In {{Notice-186-5}} and {{FIPS-186-5}}, NIST warns about side-channel and fault injection attacks, but states that deterministic ECDSA may be desirable for devices that lack good randomness. The quantum-resistant ML-DSA {{Draft-204}} under standardization by NIST uses hedged signing by default.

BSI has published {{BSI}} and researchers from BSI have co-authored two research papers {{ABFJLM17}} {{PSSLR17}} on attacks on deterministic signatures. For many industries it is important to be compliant with both RFCs and government publications, alignment between IETF, NIST, and BSI recommendations would be preferable.

Note that deriving per-message secret number deterministically, is also insecure in a multi-party signature setting {{I-D.irtf-cfrg-frost}}.

One countermeasure to entropy failures, side-channel attacks, and fault injection attacks recommended by {{Langley13}} {{RP17}} {{ABFJLM17}} {{SBBDS17}} {{PSSLR17}} {{SB18}} {{AOTZ19}} {{FG19}} and implemented in {{OpenSSL13a}} {{OpenSSL13b}} {{XEdDSA}} {{libSodium}} {{libHydrogen}} is to generate the per-message secret number from a random string, a secret key, and the message. This combines the security benefits of fully randomized per-message secret numbers with the security benefits of fully deterministic secret numbers.  Such a construction protects against key compromise due to weak random number generation, but still effectively prevents many side-channel and fault injection attacks that exploit determinism. Such a construction require minor changes to the implementation and does not increase the number of elliptic curve point multiplications and is therefore suitable for constrained IoT. Adding randomness to EdDSA is not compliant with {{RFC8032}}. {{Kampanakis16}} describes an alternative {{FIPS-186-5}} compliant approach where message specific pseudo-random information is used as an additional input to the random number generation to create per-message secret number. {{Bernstein14}} states that generation of the per-message secret number from a subset of a random string, a secret key, the message, and a message counter is common in DSA/ECDSA implementations.

This document updates {{RFC6979}} and {{RFC8032}} to recommend constructions with additional randomness for deployments where side-channel and fault injection attacks are a concern. The updates are invisible to the validator of the signature. Produced signatures remain fully compatible with unmodified ECDSA and EdDSA verifiers and existing key pairs can continue to be used. As the precise use of the noise is specified, test vectors can still be produced, and implementations can be tested against them.

# Conventions Used in This Document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

# Updates to RFC 8032 (EdDSA) {#SecEdDSA}

For Ed25519ph, Ed25519ctx, and Ed25519: In deployments where side-channel and fault injection attacks are a concern, the following step is RECOMMENDED instead of step (2) in Section 5.1.6 of {{RFC8032}}:

~~~~~~~~~~~~~~~~~~~~~~~
2.  Compute SHA-512(dom2(F, C) || Z || 000... || prefix || 000... ||
    PH(M)), where M is the message to be signed, Z is 32 octets of
    random data, the number of zeroes 000... is chosen so that the
    lengths of (dom2(F, C) || Z || 000...) and (prefix || 000...) are
    multiples of 128 octets.  Interpret the 64-octet digest as a
    little-endian integer r.
~~~~~~~~~~~~~~~~~~~~~~~

For Ed448ph and Ed448: In deployments where side-channel and fault injection attacks are a concern, the following step is RECOMMENDED instead of step (2) in Section 5.2.6 of {{RFC8032}}:

~~~~~~~~~~~~~~~~~~~~~~~
2.  Compute SHAKE256(dom4(F, C) || Z || 000... || prefix || 000... ||
    PH(M), 114), where M is the message to be signed, and Z is 57
    octets of random data, the number of zeroes 000... is chosen so
    that the length of (dom4(F, C) || Z || 000...) and (prefix ||
    000...) are multiples of 136 octets.  F is 1 for Ed448ph, 0 for
    Ed448, and C is the context to use.  Interpret the 114-octet
    digest as a little-endian integer r.
~~~~~~~~~~~~~~~~~~~~~~~

# Updates to RFC 6979 (Deterministic ECDSA)

For Deterministic ECDSA: In existing ECDSA deployments where side-channel and fault injection attacks are a concern, the following steps are RECOMMENDED instead of steps (d) and (f) in Section 3.2 of {{RFC6979}}:

~~~~~~~~~~~~~~~~~~~~~~~
d.  Set:

       K = HMAC_K(V || 0x00 || Z || 000... || int2octets(x) || 000...
           || bits2octets(h1))

    where '||' denotes concatenation.  In other words, we compute
    HMAC with key K, over the concatenation of the following, in
    order: the current value of V, a sequence of eight bits of value
    0, random data Z (of the same length as int2octets(x)), a
    sequence of zero bits 000..., the encoding of the (EC)DSA private
    key x, a sequence of zero bits 000..., and the hashed message
    (possibly truncated and extended as specified by the bits2octets
    transform).  The number of zeroes 000... is chosen so that the
    length of (V || 0x00 || Z || 000...) and (int2octets(x) ||
    000...) are multiples of the block size of the hash function.
    The HMAC result is the new value of K.  Note that the private key
    x is in the [1, q-1] range, hence a proper input for int2octets,
    yielding rlen bits of output, i.e., an integral number of octets
    (rlen is a multiple of 8).
~~~~~~~~~~~~~~~~~~~~~~~
~~~~~~~~~~~~~~~~~~~~~~~
f.  Set:

       K = HMAC_K(V || 0x01 || Z || 000... || int2octets(x) ||
           000... || bits2octets(h1))

    Note that the "internal octet" is 0x01 this time and that Z is
    newly generated random data, i.e., not reused from step (d).
~~~~~~~~~~~~~~~~~~~~~~~

When ECDSA is used with SHAKE {{SHA3}} the HMAC construction above MAY be used but it is RECOMMENDED to use the more efficient KMAC construction {{KMAC}}. SHAKE is a variable-length hash function defined as SHAKE(M, d) where the output is a d-bits-long digest of message M. When ECDSA is used with SHAKE128(M, d), it is RECOMMENDED to replace HMAC(K, M) with KMAC128(K, M, d, ""). When ECDSA is used with SHAKE256(M, d), it is RECOMMENDED to replace HMAC(K, M) with KMAC256(K, M, d, ""). {{RFC8692}} and {{FIPS-186-5}} define the use of SHAKE128 with an output length of 256 bits and SHAKE256 with an output length or 512 bits.

In new deployments, where side-channel and fault injection attacks are a concern, EdDSA with additional randomness as specified in {{SecEdDSA}} is RECOMMENDED.

# Security Considerations

The constructions in this document follow the high-level approach in {{XEdDSA}} to calculate the per-message secret number from the hash of the private key and the message, but add additional randomness into the calculation for greater resilience. This does not re-introduce the strong security requirement of randomness needed by randomized ECDSA {{FIPS-186-5}}. The randomness of Z need not be perfect but SHALL be generated by a cryptographically secure pseudo random number generator (CSPRNG) and SHALL be secret. Even if the same random number Z is used to sign two different messages, the security will be the same as deterministic ECDSA and EdDSA and an attacker will not be able to compromise the private key with algebraic means as in fully randomized ECDSA {{FIPS-186-5}}. With the construction specified in this document, two signatures over two equal messages are different which prevents information leakage in use cases where signatures but not messages are public. The construction in this document place the additional randomness before the message to align with randomized hashing methods.

{{SBBDS17}} states that {{XEdDSA}} would not prevent their attack due to insufficient mixing of the hashed private key with the additional randomness. The construction in this document aims to mitigate fault injection attacks that leverage determinism in deterministic ECDSA and EdDSA signatures (see e.g., {{ABFJLM17}}), by randomizing nonce generation. Fault injection attacks that achieve instruction skipping as in e.g., Section 3.4 of {{ABFJLM17}} are not necessarily stopped. It seems to be possible to, at the same time, also mitigate attacks that use first order differential power analysis (DPA) against the hash computation of deterministic nonces in EdDSA and ECDSA (see e.g., {{ABFJLM17}}{{SBBDS17}}). The mitigation in this document agrees with one mentioned in {{ABFJLM17}} and appears to be as effective against the referenced first order DPA attacks as the one in {{SBBDS17}}.

Another countermeasure to fault attacks is to force the signer to verify the signature in the last step of the signature generation or to calculate the signature twice and compare the results. These countermeasure would catch a single fault but would not protect against attackers that are able to precisely inject faults several times {{RP17}} {{PSSLR17}} {{SB18}}. Adding an additional sign or verification operation would also significantly affect performance, especially verification which is a heavier operation than signing in ECDSA and EdDSA.

{{ABFJLM17}} suggests using both additional randomness and a counter, which makes the signature generation stateful. While most used signatures have traditionally been stateless, stateful signatures like XMSS {{RFC8391}} and LMS {{RFC8554}} have now been standardized and deployed. {{RFC8937}} specifies a PRNG construction with a random seed, a secret key, a context string, and a nonce, which makes the random number generation stateful. The generation of the per-message secret number in this document is not stateful, but it can be used with a stateful PRNG. The exact construction in {{RFC8937}} is however not recommended in deployments where side-channel and fault injection attacks are a concern as it relies on deterministic signatures.

With the construction in this document, the repetition of the same per-message secret number for two different messages is highly unlikely even with an imperfect random number generator, but not impossible. As an extreme countermeasure, previously used secret numbers can be tracked to ensure their uniqueness for a given key, and a different random number can be used if a collision is detected. This document neither mandates nor prohibits implementations from taking such precautions.

Implementations need to follow best practices on how to protect against all side-channel attacks, not just attacks that exploit determinism, see for example {{BSI}}.

--- back

# Change log
{:removeInRFC="true" numbered="false"}

Changes from -00 to -01:

* Changed terminology to hedged signatures
* Added reference to the FIPS 204 (ML-DSA) where hedged signatures are the default.
* Added a second 000... padding that separates the context from the prefix, aligning with BSI recommendations.
* Added note that Z in step f is not reused from step d
* Added note on "internal octet" is 0x01 from RFC 6979
* Removed incorrect statement that context fit in first block
* Added more description about the construction
* Moved "For discussion" section to GitHub issue
* Editorial changes.

# Acknowledgments
{:numbered="false"}

The authors would like to thank
{{{Tony Arcieri}}},
{{{Uri Blumenthal}}},
{{{Carsten Bormann}}},
{{{Phillip Hallam-Baker}}},
{{{Chelsea Komlo}}},
{{{Quynh Dang}}},
{{{Janos Follath}}},
{{{Ilari Liusvaara}}},
{{{Jim Schaad}}},
and
{{{Ruggero Susella}}}
for their valuable comments and feedback.
