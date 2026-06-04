# References

RVZ/WIA format and Dolphin implementation:

- https://github.com/dolphin-emu/dolphin/blob/master/docs/WiaAndRvz.md
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/docs/WiaAndRvz.md
- https://github.com/dolphin-emu/dolphin/blob/master/Source/Core/DiscIO/WIABlob.cpp
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/WIABlob.cpp
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/WIABlob.h
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/WIACompression.cpp
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/VolumeWii.h
- https://bugs.dolphin-emu.org/issues/13671

Wii partition hash/encryption reconstruction:

- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/WiiEncryptionCache.cpp
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/WiiEncryptionCache.h
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/VolumeWii.cpp
- https://raw.githubusercontent.com/dolphin-emu/dolphin/master/Source/Core/DiscIO/VolumeWii.h
- https://wiibrew.org/wiki/Wii_Disc

Potential AES dependencies for Wii partition support:

- https://pypi.org/project/pycryptodomex/
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
- https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html
- https://pypi.org/project/cryptography/
- https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

Python 3.8 dependency bounds:

- https://pypi.org/pypi/zstandard/json
- https://pypi.org/pypi/zstandard/0.23.0/json
- https://pypi.org/pypi/zstandard/0.24.0/json
- https://pypi.org/pypi/cryptography/json
- https://pypi.org/pypi/cryptography/47.0.0/json
- https://pypi.org/pypi/cryptography/48.0.0/json
