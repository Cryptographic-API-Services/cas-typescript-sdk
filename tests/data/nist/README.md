# NIST CAVP vectors

`scripts/fetch-nist.mjs` (run by `npm run nist:fetch`, and by `npm run node:test`) downloads the CAVP archives below from csrc.nist.gov and checks each zip's SHA-256 before extracting the files the specs use. The extracted files are git-ignored.

| Archive | SHA-256 | Used by |
| --- | --- | --- |
| `gcmtestvectors.zip` | `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023` | `tests/aes-fips.spec.ts` |
| `kwtestvectors.zip` | `04a4a82e4de65bca505125295003f9c75a5a815afda046dc83661b8b580dfdf3` | `tests/nist-aes-kw.spec.ts` |
| `hmactestvectors.zip` | `418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd` | `tests/nist-hmac.spec.ts` |

The committed copies under `tests/data/aes/` and `tests/data/hashers/` are the older checked-in CAVP files. AES-GCM known answers now come from this download. See issue #183 for the algorithms that still have no NIST spec.
