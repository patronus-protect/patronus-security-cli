from typing import Any

from dify_plugin import ToolProvider
from dify_plugin.errors.tool import ToolProviderCredentialValidationError

from client import error_message, validate_credentials


class PatronusProvider(ToolProvider):
    def _validate_credentials(self, credentials: dict[str, Any]) -> None:
        try:
            validate_credentials(credentials)
        except Exception as error:
            raise ToolProviderCredentialValidationError(error_message(error)) from None
