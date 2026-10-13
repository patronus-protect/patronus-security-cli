from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client import client, error_message


class GetScanTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        try:
            result = client(self.runtime.credentials).get_job(tool_parameters.get('job_id', ''))
        except Exception as error:
            raise ValueError(error_message(error)) from None
        yield self.create_json_message(result)
