from typing import Any, Callable, List, Optional
from .crypto import BDACrypto
import base64
import json
import time

class ArkoseBrowserFingerprint(object):
    def __init__(self, encoded_fingerprint: str, user_agent: str, timestamp: int = None):
        now = time.time()
        self._timestamp = str(int(now - (now % 21600))) if not timestamp else timestamp
        self._key = user_agent + str(self._timestamp)

        self.crypto = BDACrypto(self._key)
        self._raw_fingeprint = json.loads(base64.b64decode(encoded_fingerprint)) # {"ct": ..., "s": ..., "iv": ... }
        self.fingerprint: list[dict[str, Any]] = json.loads(self.crypto.decrypt(self._raw_fingeprint).decode())


    def repackage(self, encode_base64: bool = True) -> str:
        repacked_bda = json.dumps(
            self.crypto.re_encrypt(json.dumps(self.fingerprint, separators=(',', ':')), self._raw_fingeprint),
            separators=(',', ':'),
            sort_keys=True
        )

        return repacked_bda if not encode_base64 else base64.b64encode(repacked_bda.encode()).decode()


    def core_key_operation(self, 
        key: str, 
        operation: Callable, 
        value: Any, 
        container: Optional[List[dict[str, Any]]] = None, 
        key_required_for_operation: Optional[bool] = True
    ) -> Any:
        container = self.fingerprint if container is None else container
        items = list(filter(lambda item: item['key'] == key, container))
        
        if not items and key_required_for_operation:
            raise KeyError(f"Key '{key}' not found in the container.")

        return operation(items[0] if key_required_for_operation else None, value, container)


    def fetch_key(self, key: str, container: Optional[List[dict[str, Any]]] = None) -> Any:
        return self.core_key_operation(key, lambda item, _, __: item['value'], None, container)


    def insert_key(self, key: str, value: Any, container: Optional[List[dict[str, Any]]] = None) -> Any:
        return self.core_key_operation(key, lambda _, value, container: container.append({'key': key, 'value': value}) or value, value, container, False)


    def edit_key(self, key: str, value: Any, container: Optional[List[dict[str, Any]]] = None) -> Any:
        return self.core_key_operation(key, lambda item, value, _: item.__setitem__('value', value) or value, value, container)


    def fetch_enhanced_fp_key(self, enhanced_fp_key: str) -> Any:
        return self.fetch_key(enhanced_fp_key, self.fetch_key("enhanced_fp"))


    def insert_enhanced_fp_key(self, key: str, value: Any) -> Any:
        return self.insert_key(key, value, self.fetch_key("enhanced_fp"))


    def edit_enhanced_fp_key(self, key: str, value: Any) -> Any:
        return self.edit_key(key, value, self.fetch_key("enhanced_fp"))