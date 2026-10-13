from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client import client, error_message, scan_body


class SubmitScanTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        try:
            result = client(self.runtime.credentials).submit(scan_body(
                tool_parameters.get('kind', 'text'), tool_parameters.get('content')))
        except Exception as error:
            raise ValueError(error_message(error)) from None
        yield self.create_json_message(result)
