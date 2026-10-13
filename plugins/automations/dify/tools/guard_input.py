from collections.abc import Generator
from typing import Any

from dify_plugin import Tool
from dify_plugin.entities.tool import ToolInvokeMessage

from client import error_message
from guard import GuardRejected, guard_input


class GuardInputTool(Tool):
    def _invoke(self, tool_parameters: dict[str, Any]) -> Generator[ToolInvokeMessage, None, None]:
        try:
            result = guard_input(self.runtime.credentials, tool_parameters.get('content'))
        except GuardRejected:
            raise
        except Exception as error:
            raise ValueError(error_message(error)) from None
        # Nothing is emitted before the complete policy check succeeds.
        yield self.create_variable_message('protected_text', result['text'])
        yield self.create_text_message(result['text'])
        yield self.create_json_message({'patronus': result['patronus']})
