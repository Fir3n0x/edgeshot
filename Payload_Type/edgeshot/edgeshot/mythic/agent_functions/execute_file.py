from mythic_container.MythicCommandBase import (
    CommandBase,
    CommandAttributes,
    CommandParameter,
    ParameterType,
    TaskArguments,
    PTTaskMessageAllData,
    PTTaskCreateTaskingMessageResponse,
)


class ExecuteFileArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self._args = [
            CommandParameter(
                name="url",
                type=ParameterType.String,
                description="URL of the file to download and prompt the victim to open",
                default_value="",
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            self.load_args_from_json_string(self.command_line)


class ExecuteFileCommand(CommandBase):
    cmd = "execute_file"
    needs_admin = False
    help_cmd = "execute_file [url]"
    description = "Download a remote file and prompt the victim to open it."
    version = 1
    author = "@Fir3n0x"
    attackmapping = []
    argument_class = ExecuteFileArguments
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
