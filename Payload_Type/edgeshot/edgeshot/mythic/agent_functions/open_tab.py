from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class OpenTabArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="url",
                type=ParameterType.String,
                description="URL to open",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class OpenTabCommand(CommandBase):
    cmd = "open_tab"
    needs_admin = False
    help_cmd = "open_tab [url]"
    description = "Open a URL in a new background tab."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = OpenTabArguments
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
