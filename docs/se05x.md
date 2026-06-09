## 1. What it is
The EdgeLock SE05x is a **ready-to-use IoT secure element** (a tamper-resistant security IC) that provides a
**root of trust at the IC level**. It runs a **Java Card OS** with a pre-installed, field-**updatable** NXP "IoT applet"
that offers key management and cryptographic services. It attaches to a host MCU/MPU over **I²C** and is driven by
NXP's **Plug & Trust middleware**. Keys can be generated, stored, and used entirely inside the chip so secrets never
leave it. Independently certified to **Common Criteria EAL 6+**.

---

## 2. Primary references
| Doc | Topic |
|---|---|
| SE050 datasheet | SE050 features / variants |
| SE051 datasheet (Rev 2.0, 2024) | SE051 features / variants |
| **[AN12413](https://www.nxp.com/docs/en/application-note/AN12413.pdf)** | SE050 APDU spec - secure object types, curves, policies (the deep technical reference) |
| **[AN13254](https://www.nxp.com/docs/en/application-note/AN13254.pdf)** | Secure attestation with SE05x |
| **[AN12570](https://www.nxp.com/docs/en/application-note/AN12570.pdf)** | Quick-start with Raspberry Pi (build + I²C) |
| **[AN13445](https://www.nxp.com/docs/en/application-note/AN13445.pdf)** | Matter using SE05x / A5000 |
| SE050 Errata sheet | Known issues (e.g. invalid-EC-key reset on SE050, fixed in SE051) |
| github.com/NXP/plug-and-trust | Open-source mini middleware |
| Product pages | nxp.com/products/SE050, /SE051, /SE052F |