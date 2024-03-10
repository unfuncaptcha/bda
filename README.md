# bda / fingerprint

View, edit, and repackage Arkose Labs Funcaptcha fingerprints

```python
>>> from unfuncaptcha_bda import ArkoseBrowserFingerprint
>>> bda="eyJjdCI6ImlvMmJUS3lrSnFObEdEU..." # encoded fingerprint
>>> user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0"
>>> timestamp = 1710028800 # passing in timestamp is optional
>>> fp = ArkoseBrowserFingerprint(bda, user_agent, timestamp)
>>> fp.fetch_key("api_type")
'js'
>>> fp.fetch_enhanced_fp_key("speech_voices_hash")
'beb5cdd6c77b3cf70bed82f758f104dd'
>>> fp.insert_enhanced_fp_key("key", "value")
'value'
>>> fp.fetch_enhanced_fp_key("key")
'value'
>>> fp.repackage()
'eyJjdCI6ImlvMmJUS3lrSnFObEdEU...'
```

## Installation

UnFuncaptcha BDA is available on PyPI:

```console
$ python -m pip install unfuncaptcha-bda
```
