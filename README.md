# Xochimilco

[![Go Reference](https://pkg.go.dev/badge/github.com/oxzi/xochimilco.svg)](https://pkg.go.dev/github.com/oxzi/xochimilco)
[![Go](https://github.com/oxzi/xochimilco/actions/workflows/go.yml/badge.svg)](https://github.com/oxzi/xochimilco/actions/workflows/go.yml)
[![REUSE status](https://api.reuse.software/badge/github.com/oxzi/xochimilco)](https://api.reuse.software/info/github.com/oxzi/xochimilco)

An implementation of the [Signal Protocols][signal-docs] [X3DH][signal-x3dh] and [Double Ratchet][signal-double-ratchet].
Plus a simple straightforward usable E2E encryption library build on top, named Xochimilco.

For both implementation details and examples, take a look at the [documentation][go-doc].

Some background, the [lake Xochimilco][wiki-xochimilco] seems to be the last native habitat for the [axolotl][wiki-axolotl].
This salamander, also called _Mexican walking fish_, has incredibly self healing abilities.
For this reason, the Double Ratchet algorithm was initially named after this animal.

[go-doc]: https://pkg.go.dev/github.com/oxzi/xochimilco
[signal-docs]: https://signal.org/docs/
[signal-x3dh]: https://signal.org/docs/specifications/x3dh/
[signal-double-ratchet]: https://signal.org/docs/specifications/doubleratchet/
[wiki-axolotl]: https://en.wikipedia.org/wiki/Axolotl
[wiki-xochimilco]: https://en.wikipedia.org/wiki/Lake_Xochimilco
